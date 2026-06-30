#ifndef DETOURMODKIT_SCAN_HPP
#define DETOURMODKIT_SCAN_HPP

/**
 * @file scan.hpp
 * @brief The single public surface of the v4 scan module: pattern matching, candidate-ladder
 *        resolution, and the standalone RIP-relative / string-xref / code-constant resolvers.
 * @details This header is the entire public scan API. It is intentionally complete: every distinct
 *          v3 scanner capability is exposed here in v4 idiom (Address / Region / Pattern / Result),
 *          so v4 is not a capability regression. The engine that implements these (the SIMD matcher,
 *          the VirtualQuery page walk, hooked-prologue recovery, the x86 decoder) lives under
 *          `src/internal/` and is never installed: an installed header is a public compile contract
 *          regardless of namespace, so the engine stays physically out of the include tree. The only
 *          implementation detail this header pulls is `detail/pattern_core.hpp`, the inline storage
 *          and constexpr parser that `Pattern` holds by value (it must be compile-visible for the
 *          consteval `literal()` path and is allowlisted on those grounds).
 *
 *          Vocabulary:
 *          - A Pattern is a compiled AOB mini-DSL string. It owns its bytes/mask inline (no heap),
 *            caches the rarest-byte scan anchor, and remembers the optional `|` result offset.
 *          - scan() locates a Pattern in a Region. resolve() runs a Candidate ladder: an ordered set
 *            of resolution strategies (byte scan, RIP-relative, RTTI vtable, string xref) tried until
 *            one turns evidence into a confident game address.
 *          - The free resolve_rip_relative / find_string_xref / read_code_constant helpers expose the
 *            individual backends for callers that resolve a single piece of evidence directly.
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
#include <string>
#include <string_view>
#include <variant>
#include <vector>

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

        /// The `|` result offset (0 when the pattern carries no offset marker).
        [[nodiscard]] constexpr std::size_t offset() const noexcept { return m_data.offset; }

        /// View over the compiled pattern bytes (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> bytes() const noexcept
        {
            return std::span<const std::byte>(m_data.bytes.data(), m_data.length);
        }

        /// View over the per-byte match mask (length == size()).
        [[nodiscard]] constexpr std::span<const std::byte> mask() const noexcept
        {
            return std::span<const std::byte>(m_data.mask.data(), m_data.length);
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
         * @brief Tests whether the pattern matches the bytes at the start of @p window.
         * @param window The candidate byte window; must be at least size() bytes to match.
         * @return True when every masked byte agrees.
         * @details Applies the same compare the scan engine uses, expressed per byte: a position matches when
         *          (memory ^ pattern) & mask is zero for every byte, so wildcard bytes (mask 0x00) always agree and a
         *          nibble mask (0xF0 / 0x0F) compares only the fixed nibble. A window shorter than the pattern cannot
         *          match.
         * @note Callback-safe -- a pure masked byte compare with no allocation, I/O, or locking.
         */
        [[nodiscard]] constexpr bool matches_at(std::span<const std::byte> window) const noexcept
        {
            if (window.size() < m_data.length)
            {
                return false;
            }
            for (std::size_t index = 0; index < m_data.length; ++index)
            {
                const std::byte masked_diff = (window[index] ^ m_data.bytes[index]) & m_data.mask[index];
                if (masked_diff != std::byte{0x00})
                {
                    return false;
                }
            }
            return true;
        }

    private:
        // Private so the only ways to obtain a Pattern are the validating factories; a default-constructed or
        // arbitrary-buffer Pattern can never exist.
        constexpr explicit Pattern(const detail::PatternBuffer &data) noexcept : m_data{data} {}

        detail::PatternBuffer m_data{};
    };

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
        /// One byte per character (char / std::string literals).
        Utf8,
        /// Two bytes per character, little-endian (wchar_t / L"" on Windows).
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
        /// Best-effort prologue back-scan from the instruction (heuristic).
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
     *          RIP-relative reference to it. Strings survive game updates far better than the code bytes around them, so
     *          a string xref is the most update-resilient anchor source. @ref text is a non-owning view into caller
     *          storage; this query is for the immediate find_string_xref() call. A stored string-xref Candidate owns
     *          its literal independently (see Candidate::string_xref) and rebuilds a view of this shape at resolve time.
     */
    struct StringRefQuery
    {
        /// Literal content (no quotes); borrowed for the call.
        std::string_view text;
        /// How it is stored in the image.
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
         *          `lea`/`mov`, ...), at the cost of a full decode per instruction. Both apply the same exact-target
         *          and single-reference uniqueness guards, so broad mode adds coverage without relaxing fail-closed
         *          behaviour.
         */
        bool broad_match = false;
    };

    /**
     * @brief Resolves a string-reference anchor inside one mapped image.
     * @param query The string and how to interpret its reference.
     * @param scope Module image to search; defaults to the host executable.
     * @return The referencing-instruction (or enclosing-function, or pointer-slot) address, or an Error.
     * @details Two fail-closed phases. Phase 1 locates the single occurrence of @p query.text in the scope's readable
     *          pages (zero -> StringNotFound, more than one -> StringAmbiguous; the linker pools identical literals, so
     *          a non-unique string is genuinely ambiguous). Phase 2 scans the scope's execute-readable pages for the
     *          single RIP-relative reference whose resolved absolute target is that string (zero -> NoReference, more
     *          than one -> AmbiguousReference). A reference counts only when its resolved target exactly equals the
     *          located string address, which is itself a plausible in-image pointer, so the equality subsumes the
     *          plausible-userspace floor without a separate check. The xref is RIP-relative, so the result is
     *          ASLR-correct by construction.
     * @note Not noexcept: the broad-match phase may allocate while decoding. Setup/control-plane only.
     */
    [[nodiscard]] Result<Address> find_string_xref(const StringRefQuery &query, Region scope = Region::host());

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
     *          construction: a Direct candidate cannot accidentally carry a string-xref query, and there are no parallel
     *          optional fields that can drift out of sync. The four factories are the only way to build one (the default
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
         * @note Setup/control-plane only: builds an owned Candidate (string + Pattern copy); assemble ladders at init.
         */
        [[nodiscard]] static Candidate rip_relative(std::string name, Pattern pattern, std::ptrdiff_t displacement_at,
                                                    std::size_t instruction_length)
        {
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
        /// Candidate ladder that resolves to the instruction site (a Direct candidate with walk_back 0). Borrowed.
        std::span<const Candidate> site;
        /// Which operand field to read: an immediate or a memory displacement.
        OperandKind kind = OperandKind::Immediate;
        /// Index into the instruction's VISIBLE operands, as counted in a disassembler.
        std::uint8_t operand_index = 0;
        /// 0 returns the decoder's already-sign-extended value; > 0 narrows to this many bytes then re-sign-extends.
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
     *          Fail-closed: a site that no longer decodes (DecodeFailed), whose operand is the wrong kind
     *          (UnexpectedShape), or whose operand index is out of range (OperandOutOfRange) returns a typed error
     *          rather than a guess. A RIP-relative memory operand is resolved to its absolute target.
     * @note Not noexcept: resolving the site allocates. Setup/control-plane only.
     */
    [[nodiscard]] Result<std::int64_t> read_code_constant(const CodeConstant &code_constant,
                                                          Region scope = Region::host());

    /**
     * @struct Hit
     * @brief A resolved address paired with the name of the candidate that produced it; owns its name.
     * @details winning_name is a std::string copied from the winning Candidate, so it stays valid for the lifetime of
     *          the Hit no matter what happens to the request or its ladder.
     */
    struct Hit
    {
        /// The resolved absolute address.
        Address address;
        /// A copy of the winning candidate's name.
        std::string winning_name;
    };

    /**
     * @struct ScanRequest
     * @brief A non-owning resolution request: a candidate ladder plus the scope and policy to resolve it under.
     * @details ladder and label are NON-owning views, so a ScanRequest is for a request built and consumed in one
     *          expression (a temporary handed straight to resolve() outlives the call). To store or pass a request
     *          around, use OwnedScanRequest, or build a borrowed one through borrow() so the lifetime-bound diagnostic
     *          can ride its parameters (the attribute cannot annotate a data member).
     */
    struct ScanRequest
    {
        /// Candidates tried in order (after applying @ref order); the first that resolves uniquely wins.
        std::span<const Candidate> ladder;
        /// Optional label for diagnostics; non-owning.
        std::string_view label{};
        /// The memory range to resolve within; defaults to the host process image.
        Region scope = Region::host();
        /// When every direct candidate misses, rebuild each Direct prologue as a near/far JMP and retry.
        bool prologue_fallback = false;
        /// Fail closed on an ambiguous byte match (a second occurrence in scope) rather than taking the first.
        bool require_unique = true;
        /// How the ladder is ordered before it is tried.
        CandidateOrder order = CandidateOrder::AsDeclared;
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
                                     bool prologue_fallback = false, bool require_unique = true,
                                     CandidateOrder order = CandidateOrder::AsDeclared) noexcept;

    /**
     * @struct OwnedScanRequest
     * @brief An owning resolution request for stored or deferred resolution.
     * @details Owns its ladder and label, so it is the safe shape to keep inside a registration or any structure that
     *          outlives the expression that built it. The structural guarantee that stored entry points take
     *          OwnedScanRequest (never a borrowed ScanRequest) is the primary defense against a dangling ladder span;
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
        /// Enable hooked-prologue recovery on a full direct miss.
        bool prologue_fallback = false;
        /// Fail closed on an ambiguous byte match.
        bool require_unique = true;
        /// Ladder ordering policy.
        CandidateOrder order = CandidateOrder::AsDeclared;

        /**
         * @brief Returns a borrowed ScanRequest viewing this object's owned storage.
         * @return A ScanRequest whose ladder/label alias *this; valid only while this OwnedScanRequest lives.
         */
        [[nodiscard]] ScanRequest view() const noexcept DMK_LIFETIMEBOUND
        {
            return ScanRequest{
                .ladder = ladder,
                .label = label,
                .scope = scope,
                .prologue_fallback = prologue_fallback,
                .require_unique = require_unique,
                .order = order,
            };
        }
    };

    /**
     * @brief Writes the index permutation @p order implies for @p ladder into @p out.
     * @param order The ordering policy.
     * @param ladder The candidate ladder to order.
     * @param out Destination for the permutation; receives up to min(ladder.size(), out.size()) indices.
     * @return The number of indices written.
     * @details Pure index math, no allocation: it emits an ordering, never touches the candidates. AsDeclared is the
     *          identity permutation. UniqueFirst is a stable three-pass partition (unique-only text tiers, then anchored
     *          byte patterns, then the rest), declared order preserved within each group.
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
     *          in-scope plausible address, or (for a text tier) resolves through its unique-only backend, wins. On a
     *          full direct miss with prologue_fallback set, each Direct candidate's prologue is rebuilt as a near/far
     *          JMP and retried to recover a target another mod already inline-hooked. May allocate, so it is NOT
     *          noexcept; the only throwing path is allocation failure.
     * @note Setup/control-plane only: a cascade resolve walks the image and is a startup-time operation.
     */
    [[nodiscard]] Result<Hit> resolve(const ScanRequest &request);

    /**
     * @brief Resolves a batch of requests concurrently, returning one Result per request in input order.
     * @param requests The requests to resolve.
     * @param max_workers Upper bound on worker threads (0 = auto-select from hardware concurrency).
     * @return One Result<Hit> per input request, in order.
     * @details noexcept by contract: a per-request allocation failure is reported as Error{OutOfMemory} and any other
     *          per-request exception leaves that slot at the seeded Error{NoMatch}, so one failing request never sinks
     *          the batch. The result vector is allocated and seeded up front; if that initial allocation itself fails
     *          under true out-of-memory, the function returns an empty vector, so a caller that indexes the result must
     *          treat a size mismatch as a whole-batch allocation failure.
     * @note Setup/control-plane only: spawns a worker pool and allocates; a startup-time batch, not a per-frame call.
     */
    [[nodiscard]] std::vector<Result<Hit>> resolve_batch(std::span<const ScanRequest> requests,
                                                         std::size_t max_workers = 0) noexcept;

    /**
     * @brief Scans one Pattern over a known scope and returns the Nth match address.
     * @param pattern The compiled signature.
     * @param scope The memory range to search.
     * @param occurrence Which match to return (1-based). 1 = first match. 0 yields NoMatch.
     * @param pages Which page-protection class to accept (Readable superset by default, or Executable code-only).
     * @return The address of the Nth match (adjusted by the Pattern's `|` offset), or an Error.
     * @details Page-gated and safe by default: it walks @p scope through the OS page map and reads only committed pages
     *          of the requested class under a fault guard, so an unmapped or guard page inside the scope is skipped
     *          rather than faulting the host. A match that straddles two adjacent accepted regions is still found (the
     *          sweep carries a pattern_len-1 overlap across a contiguous run). noexcept; an allocation failure while
     *          preparing the scan surfaces as Error{OutOfMemory}. For the raw, caller-guarantees-readability primitive
     *          use unchecked::find_pattern.
     * @note Setup/control-plane only: walks the scope through the OS page map; a startup-time scan, not a per-frame
     * call.
     */
    [[nodiscard]] Result<Address> scan(const Pattern &pattern, Region scope, std::size_t occurrence = 1,
                                       Pages pages = Pages::Readable) noexcept;

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
     * @param instruction_length Total length of the instruction in bytes.
     * @return The resolved absolute address (`instruction + instruction_length + disp32`), or an Error.
     * @details The displacement is read under an SEH fault guard. A resolved address that is not a plausible user-mode
     *          pointer is rejected with ErrorCode::ImplausibleTarget rather than returned. For `FF 15`/`FF 25` forms the
     *          resolved value is the pointer slot, itself an in-image address.
     * @note Callback-safe: a guarded read plus pointer arithmetic, no allocation.
     */
    [[nodiscard]] Result<Address> resolve_rip_relative(Address instruction, std::size_t displacement_offset,
                                                       std::size_t instruction_length) noexcept;

    /**
     * @brief Scans forward in @p search for an opcode prefix, then resolves the RIP-relative target that follows it.
     * @param search The region to scan; the disp32 is assumed to immediately follow the matched prefix.
     * @param opcode_prefix The opcode byte sequence to search for.
     * @param instruction_length Total length of the instruction in bytes.
     * @return The resolved absolute address, or an Error.
     * @details Matching is first-prefix-wins. For indirect-call / indirect-jump forms (`FF 15`/`FF 25`) the returned
     *          address is the pointer slot, not the final target. The resolved target is gated by the same
     *          ImplausibleTarget check as resolve_rip_relative. When a signature may be ambiguous, anchor it through
     *          resolve() (which enforces per-candidate uniqueness) instead.
     * @note Callback-safe: a bounded scan plus a guarded read, no allocation.
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
     * @brief Flattens a resolve Result to its address, or a null Address on failure.
     * @details The single blessed convenience for the address-or-nothing shape. It is a LEGACY/compat adapter, not the
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
     * LEGACY/compat
     *          status: prefer handling the Error in new code.
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
