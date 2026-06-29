#ifndef DETOURMODKIT_SCAN_HPP
#define DETOURMODKIT_SCAN_HPP

/**
 * @file scan.hpp
 * @brief The v4 scanning surface, centered on the value-semantic compiled AOB Pattern.
 * @details A Pattern is the compiled form of an AOB mini-DSL string ("48 8B 05 ?? ?? ?? ??"): it owns its bytes and
 *          mask inline (no heap), caches the rarest-byte scan anchor, and remembers the optional `|` result offset.
 *          Two entry points construct one. compile() parses a runtime string and returns a Result, so a bad pattern
 *          is a recoverable error rather than undefined behaviour. literal() parses an in-source string literal at
 *          COMPILE time and returns a Pattern by value, so a typo in a hard-coded signature is a build error and an
 *          in-source candidate ladder stays a constexpr-friendly value with no Result to unwrap.
 */

#include "DetourModKit/defines.hpp"
#include "DetourModKit/detail/pattern_core.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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
     * @enum Mode
     * @brief The resolution strategy a Candidate uses to turn a signature into an address.
     * @details v3 shipped these as four parallel resilience tiers reached through six `resolve_cascade_*` overloads. In
     *          v4 the tier is data on the Candidate, not a function name, so a ladder can interleave them freely and
     *          the resolver dispatches on this field. The two byte tiers (Direct, RipRelative) scan a compiled Pattern;
     *          the two text tiers (RttiVtable, StringXref) resolve a name/literal through a dedicated backend and are
     *          unique-only by construction (they fail closed on ambiguity regardless of the request's require_unique).
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
     * @details Merged from v3's `profile.hpp`. AsDeclared preserves the caller's array order. UniqueFirst promotes the
     *          tiers least likely to mis-resolve so a confident hit is reached before a looser fallback is consulted:
     *          the unique-only text tiers (RttiVtable, StringXref) lead, then anchored byte patterns (a fully-known
     *          rarest byte makes a Pattern far more selective), then the remaining byte patterns. Reordering never
     *          changes which addresses are valid: every candidate is still verified (unique-in-scope when required,
     *          in-scope, plausibly resolved), so a promoted candidate can only be tried earlier, never accepted on
     *          weaker evidence.
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
     * @class Candidate
     * @brief One resilience tier in a resolution ladder: a strategy plus the signature it resolves, owning its strings.
     * @details A Candidate owns its name and (for the text tiers) its query string, so the legacy hazard where a
     *          ResolveHit::winning_name or a Landmark::expected_mangled aliased a caller table that later went out of
     *          scope is structurally impossible here. The four factories are the only way to build one: the default
     *          constructor is private, the payload members are private, and the class is not an aggregate, so a
     *          Candidate can only exist with a coherent (mode, payload) pairing. The byte tiers carry a compiled
     *          Pattern (held in an optional because Pattern has no empty state of its own) and the RIP offsets; the
     *          text tiers carry the query and leave the Pattern absent.
     */
    class Candidate
    {
    public:
        /**
         * @brief A Direct byte-scan candidate: the resolved address is at the match site plus a fixed walk-back.
         * @param name Human-readable label, carried into the winning Hit. Owned.
         * @param pattern The compiled signature to scan for.
         * @param walk_back Signed byte delta added to the match (negative walks backward); 0 returns the match itself.
         * @return The constructed Candidate.
         */
        [[nodiscard]] static Candidate direct(std::string name, Pattern pattern, std::ptrdiff_t walk_back = 0);

        /**
         * @brief A RIP-relative byte-scan candidate: the resolved address is read from a disp32 the match spans.
         * @param name Human-readable label, carried into the winning Hit. Owned.
         * @param pattern The compiled signature to scan for.
         * @param displacement_at Byte offset from the match to the signed 4-byte displacement field.
         * @param instruction_length Total length of the referencing instruction (the next-IP base for the disp).
         * @return The constructed Candidate.
         * @details The target is `(match + instruction_length) + sign_extend(disp32 @ (match + displacement_at))`, read
         *          under a fault guard, so a corrupt displacement is a miss rather than a host fault.
         */
        [[nodiscard]] static Candidate rip_relative(std::string name, Pattern pattern, std::ptrdiff_t displacement_at,
                                                    std::size_t instruction_length);

        /**
         * @brief An RTTI-vtable candidate: resolves the primary vtable of an MSVC-mangled type name.
         * @param name Human-readable label, carried into the winning Hit. Owned.
         * @param mangled The MSVC decorated type name, e.g. ".?AVCameraManager@@". Owned.
         * @return The constructed Candidate.
         * @details Unique-only: an ambiguous name (two primaries) fails closed and the ladder falls through.
         */
        [[nodiscard]] static Candidate rtti_vtable(std::string name, std::string mangled);

        /**
         * @brief A string-xref candidate: resolves the unique RIP-relative reference to an immutable string literal.
         * @param name Human-readable label, carried into the winning Hit. Owned.
         * @param literal The exact string content to anchor on (no quotes). Owned.
         * @return The constructed Candidate.
         * @details Strings outlive the code around them across game updates, so a string xref is the most
         *          update-resilient anchor. Unique-only: a pooled literal or a second reference fails closed.
         */
        [[nodiscard]] static Candidate string_xref(std::string name, std::string literal);

        /// Human-readable label; carried verbatim into the winning Hit.
        [[nodiscard]] const std::string &name() const noexcept { return m_name; }

        /// Returns the resolution strategy this tier uses.
        [[nodiscard]] Mode mode() const noexcept { return m_mode; }

        /// Returns the byte-tier pattern, or nullptr for text tiers.
        [[nodiscard]] const Pattern *pattern() const noexcept { return m_pattern ? &*m_pattern : nullptr; }

        /// Returns the MSVC mangled type name or string literal for text tiers.
        [[nodiscard]] std::string_view query() const noexcept { return m_query; }

        /// Returns the Direct walk-back or RipRelative displacement-field offset.
        [[nodiscard]] std::ptrdiff_t displacement() const noexcept { return m_displacement; }

        /// Returns the RipRelative instruction length.
        [[nodiscard]] std::size_t instruction_length() const noexcept { return m_instruction_length; }

    private:
        // Private so the four validating factories are the only construction path; a Candidate with a mismatched
        // (mode, payload) pairing can never exist, and a stray `Candidate{...}` aggregate-init does not compile.
        Candidate() = default;

        std::string m_name;
        Mode m_mode = Mode::Direct;
        std::optional<Pattern> m_pattern;
        std::string m_query;
        std::ptrdiff_t m_displacement = 0;
        std::size_t m_instruction_length = 0;
    };

    /**
     * @struct Hit
     * @brief A resolved address paired with the name of the candidate that produced it; owns its name.
     * @details winning_name is a `std::string` copied from the winning Candidate, so it stays valid for the lifetime of
     *          the Hit no matter what happens to the request or its ladder. This is the owning successor to v3's
     *          ResolveHit, whose `winning_name` aliased the caller's candidate table.
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
     * @details Replaces the six v3 `resolve_cascade_*` overloads with one shape where scope and prologue fallback are
     *          fields, not name suffixes. ladder and label are NON-owning views, so a ScanRequest is for a request that
     *          is built and consumed in one expression (a temporary handed straight to resolve() outlives the call). To
     *          store or pass a request around, use OwnedScanRequest, or build a borrowed one through borrow() so the
     *          lifetime-bound diagnostic can ride its parameters (the attribute cannot annotate a data member).
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
     * @param ladder The candidate ladder; borrowed, must outlive the request.
     * @param label Optional diagnostic label; borrowed.
     * @param scope The resolution scope; defaults to the host image.
     * @param prologue_fallback Enable hooked-prologue recovery on a full direct miss.
     * @param require_unique Fail closed on an ambiguous byte match.
     * @param order Ladder ordering policy.
     * @return A ScanRequest viewing @p ladder and @p label.
     * @details DMK_LIFETIMEBOUND on the borrowed parameters lets Clang/MSVC warn when a temporary ladder/label is
     *          passed (the attribute is a parameter/return annotation and cannot sit on the ScanRequest members). MinGW
     *          GCC has no such attribute, so the build there relies on the owning/borrowed split plus
     *          `-Wdangling-reference` instead. For a stored or deferred request, prefer OwnedScanRequest.
     */
    [[nodiscard]] ScanRequest borrow(std::span<const Candidate> ladder DMK_LIFETIMEBOUND,
                                     std::string_view label DMK_LIFETIMEBOUND = {}, Region scope = Region::host(),
                                     bool prologue_fallback = false, bool require_unique = true,
                                     CandidateOrder order = CandidateOrder::AsDeclared) noexcept;

    /**
     * @struct OwnedScanRequest
     * @brief An owning resolution request for stored or deferred resolution.
     * @details Owns its ladder and label, so it is the safe shape to keep inside a HookSpec, a Session registration, or
     *          any structure that outlives the expression that built it. The structural guarantee that stored entry
     *          points take OwnedScanRequest (never a borrowed ScanRequest) is the primary defense against a dangling
     *          ladder span; @ref view rebuilds a borrowed ScanRequest over this object's storage on demand, with the
     *          lifetime-bound macro on the implicit object so a view() of a temporary warns.
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
     *          identity permutation. UniqueFirst is a stable three-pass partition (unique-only text tiers, then
     *          anchored byte patterns, then the rest), declared order preserved within each group. The resolver uses
     *          this to lay out its try order; it is exposed so a caller can inspect or reuse the same ordering.
     */
    [[nodiscard]] std::size_t order_candidates(CandidateOrder order, std::span<const Candidate> ladder,
                                               std::span<std::size_t> out) noexcept;

    /**
     * @brief Resolves a candidate ladder to a single address, trying each tier until one resolves uniquely.
     * @param request The ladder, scope, and policy to resolve.
     * @return The resolved Hit, or an Error describing why no candidate resolved.
     * @details The whole resolver surface in one call (it replaces the six v3 `resolve_cascade_*` overloads).
     * Candidates
     *          are tried in @ref ScanRequest::order order; the first that (for a byte tier) matches in scope, passes
     *          the uniqueness gate when required, and resolves to an in-scope, plausible address, or (for a text tier)
     *          resolves through its unique-only backend, wins. On a full direct miss with prologue_fallback set, each
     *          Direct candidate's prologue is rebuilt as a near/far JMP and retried to recover a target another mod
     *          already inline-hooked. May allocate (it compiles each byte Pattern into the engine's scan form), so it
     *          is NOT noexcept; the only throwing path is allocation failure, which surfaces as the function's
     *          exception rather than the Result.
     * @note Setup/control-plane only: a cascade resolve walks the image and is a startup-time operation, never a
     *       per-frame one.
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
     *          under true out-of-memory, the function returns an empty vector (there is no per-request storage to
     *          report into), so a caller that indexes the result must treat a size mismatch as a whole-batch
     *          allocation failure. This deletes the try/catch + serial-fallback compensation consumers hand-rolled
     *          around the legacy batch.
     */
    [[nodiscard]] std::vector<Result<Hit>> resolve_batch(std::span<const ScanRequest> requests,
                                                         std::size_t max_workers = 0) noexcept;

    /**
     * @brief Scans one Pattern over a known scope and returns the first match address.
     * @param pattern The compiled signature.
     * @param scope The memory range to search.
     * @return The address of the first match (adjusted by the Pattern's `|` offset), or an Error.
     * @details Page-gated and safe by default: it walks @p scope through the OS page map and reads only committed,
     *          readable pages under a fault guard, so an unmapped or guard page inside the scope is skipped rather than
     *          faulting the host. noexcept; an allocation failure while preparing the scan surfaces as
     *          Error{OutOfMemory} rather than an exception. For the raw, caller-guarantees-readability primitive use
     *          unchecked::find_pattern.
     */
    [[nodiscard]] Result<Address> scan(const Pattern &pattern, Region scope) noexcept;

    /**
     * @brief Flattens a resolve Result to its address, or a null Address on failure.
     * @param result The resolve result.
     * @return result->address on success, a null Address otherwise.
     * @details The single blessed convenience for the address-or-nothing shape (it deletes the scattered `.value_or(0)`
     *          flatten consumers wrote at every call site). It is a LEGACY/compat adapter, not the primary contract:
     *          new code resolves through Result and handles the Error. or_null appearing on a happy path is a smell.
     *          Header-inline because Hit and Result<Hit> are complete here, so it costs no scan.cpp dependency.
     */
    [[nodiscard]] inline Address or_null(const Result<Hit> &result) noexcept
    {
        return result ? result->address : Address{};
    }

    /**
     * @brief Flattens a resolve Result to its address, or a caller-chosen fallback on failure.
     * @param result The resolve result.
     * @param fallback The address to return when @p result holds an Error (a null Address by default).
     * @return result->address on success, @p fallback otherwise.
     * @details The general, non-default form of or_null (`or_null(r)` is `address_or(r, Address{})`). Same
     * LEGACY/compat
     *          status: prefer handling the Error in new code.
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
         * @return A pointer to the first match (adjusted by the Pattern's `|` offset), or nullptr if not found.
         * @details The unsafe twin of scan(): it performs no page filtering and uses raw SIMD/memchr loads, so an
         *          unreadable byte in @p region faults the host. It is quarantined in `unchecked` precisely because its
         *          contract is "caller proved readability"; the return is a raw pointer, not a Result, because there is
         *          no recoverable error to report. noexcept; an allocation failure preparing the scan returns nullptr.
         */
        [[nodiscard]] const std::byte *find_pattern(Region region, const Pattern &pattern) noexcept;
    } // namespace unchecked

} // namespace DetourModKit::scan

#endif // DETOURMODKIT_SCAN_HPP
