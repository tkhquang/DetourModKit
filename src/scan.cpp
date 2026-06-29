/**
 * @file scan.cpp
 * @brief Implementation of the v4 scan resolver surface: Candidate factories, ordering, resolve / resolve_batch / scan,
 *        the bounded haystack-frequency anchor override, and hooked-prologue recovery.
 * @details This translation unit expresses the resolver in the v4 Address / Region / Error vocabulary on top of the
 *          existing, battle-tested scan-engine primitives rather than reimplementing them: the page-gated SIMD scan
 *          (scan_module_readable / scan_module_executable), the fault-guarded reads (Memory::seh_read*), the
 *          plausibility / in-range screens (plausible_userspace_ptr / contains), the reverse-RTTI walk
 *          (Rtti::vtable_for_type), the string-xref backend (Scanner::find_string_xref), the jump decoders
 *          (x86_decode.hpp), and the fork-join batch driver (run_fork_join). The v3 cascade's six resolve_cascade_*
 *          overloads collapse into one resolve(ScanRequest), where scope, ordering, uniqueness, and prologue fallback
 *          are request fields rather than function names. The one genuinely new mechanism is the runtime
 *          haystack-frequency anchor: it overrides the Pattern's compile-time rarest-byte anchor with the byte rarest
 *          in the current image, and falls back to the compile-time anchor when no usable haystack sample is available.
 *          The anchor choice is correctness-neutral; it changes only which byte the prefilter sweeps for.
 */

#include "DetourModKit/scan.hpp"

#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"
#include "DetourModKit/scanner.hpp"

#include "fork_join.hpp"
#include "scanner_internal.hpp"
#include "x86_decode.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace scan
    {
        namespace
        {
            // Convert a v4 Region into the engine's half-open ModuleRange [base, end). An empty Region (the fail-closed
            // result every Region factory returns when its scope cannot be resolved) yields an invalid ModuleRange,
            // which both the page-gated scanners and the contains() screen treat as "resolve nothing".
            [[nodiscard]] Memory::ModuleRange to_module_range(Region scope) noexcept
            {
                return Memory::ModuleRange{scope.base.raw(), scope.end().raw()};
            }

            // Build the engine's heap-backed CompiledPattern from a v4 value Pattern. anchor_index is the position the
            // scan should prefilter on, already translated to the engine's sentinel convention (anchor == size() means
            // "no fully-known byte", which the engine handles with a degenerate masked compare). Allocates two small
            // vectors, so every caller on a noexcept path guards this against std::bad_alloc.
            [[nodiscard]] Scanner::CompiledPattern to_compiled(const Pattern &pattern, std::size_t anchor_index)
            {
                const std::span<const std::byte> bytes = pattern.bytes();
                const std::span<const std::byte> mask = pattern.mask();
                Scanner::CompiledPattern compiled;
                compiled.bytes.assign(bytes.begin(), bytes.end());
                compiled.mask.assign(mask.begin(), mask.end());
                compiled.offset = static_cast<std::ptrdiff_t>(pattern.offset());
                compiled.anchor = anchor_index;
                return compiled;
            }

            // Bounded haystack sampling budget. A byte-frequency ranking needs only a representative sample, not the
            // whole image: 64 page reads (256 KiB) strided across the scope are ample to rank 256 byte values, and the
            // fixed cap keeps anchor selection a constant cost regardless of scope size so it never approaches the cost
            // of the scan it accelerates. Scopes larger than the budget ceiling (a whole-process window, terabytes of
            // mostly-unmapped address space) are not sampled at all: the sample would be unrepresentative and would pay
            // for dozens of guaranteed page faults, so those fall back to the compile-time anchor.
            constexpr std::size_t SAMPLE_PAGE = 0x1000;
            constexpr std::size_t SAMPLE_MAX_PAGES = 64;
            constexpr std::size_t SAMPLE_MIN_BYTES = SAMPLE_PAGE;
            constexpr std::size_t SAMPLE_MAX_SCOPE = std::size_t{512} * 1024 * 1024;

            struct HaystackHistogram
            {
                std::array<std::uint32_t, 256> counts{};
                std::size_t sampled = 0;
            };

            // Sample a bounded, strided set of pages from the scope and tally a 256-bin byte-frequency histogram. Reads
            // go through seh_read_bytes one page at a time, so an unmapped / guard page inside the scope is skipped
            // rather than faulting the host; the stride spreads the sample across .text and .rdata / .data so the
            // frequencies reflect the whole image, not just its first pages. Entirely stack-based (the histogram and
            // the page buffer are locals), so it never allocates and is safe to call from the noexcept scan paths.
            [[nodiscard]] HaystackHistogram sample_haystack(Region scope) noexcept
            {
                HaystackHistogram histogram;
                const std::uintptr_t base = scope.base.raw();
                if (base == 0 || scope.size == 0 || scope.size > SAMPLE_MAX_SCOPE)
                {
                    return histogram;
                }
                const std::size_t total_pages = (scope.size + SAMPLE_PAGE - 1) / SAMPLE_PAGE;
                const std::size_t stride = (total_pages > SAMPLE_MAX_PAGES) ? (total_pages / SAMPLE_MAX_PAGES) : 1;
                std::array<std::uint8_t, SAMPLE_PAGE> buffer{};
                std::size_t pages_read = 0;
                for (std::size_t page = 0; page < total_pages && pages_read < SAMPLE_MAX_PAGES; page += stride)
                {
                    const std::uintptr_t page_address = base + static_cast<std::uintptr_t>(page) * SAMPLE_PAGE;
                    const std::size_t remaining = scope.size - page * SAMPLE_PAGE;
                    const std::size_t want = (remaining < SAMPLE_PAGE) ? remaining : SAMPLE_PAGE;
                    if (!Memory::seh_read_bytes(page_address, buffer.data(), want))
                    {
                        // A page that faults mid-read is skipped; the sample stays a valid (smaller) lower bound.
                        continue;
                    }
                    for (std::size_t i = 0; i < want; ++i)
                    {
                        ++histogram.counts[buffer[i]];
                    }
                    histogram.sampled += want;
                    ++pages_read;
                }
                return histogram;
            }

            // When a sufficient haystack sample exists, pick the pattern's fully-known byte whose value is rarest in
            // this image (the most selective prefilter for this haystack), overriding the compile-time rarest-byte
            // anchor the Pattern carries; otherwise fall back to that compile-time anchor. Returns the engine "no
            // fully-known byte" sentinel (size()) when the pattern has no full byte. Correctness-neutral: the anchor
            // only selects which single byte the memchr prefilter sweeps for; the full masked compare still decides
            // every accepted position.
            [[nodiscard]] std::size_t choose_scan_anchor(const Pattern &pattern,
                                                         const HaystackHistogram &histogram) noexcept
            {
                const std::size_t size = pattern.size();
                if (histogram.sampled < SAMPLE_MIN_BYTES)
                {
                    return pattern.has_anchor() ? pattern.anchor_index() : size;
                }
                const std::span<const std::byte> bytes = pattern.bytes();
                const std::span<const std::byte> mask = pattern.mask();
                std::size_t best_index = size;
                std::uint32_t best_count = 0;
                for (std::size_t i = 0; i < size; ++i)
                {
                    if (mask[i] != std::byte{0xFF})
                    {
                        // Only a fully-known byte gives the prefilter one exact value to memchr for; nibble / wildcard
                        // positions cannot anchor.
                        continue;
                    }
                    const std::uint32_t count = histogram.counts[std::to_integer<std::uint8_t>(bytes[i])];
                    if (best_index == size || count < best_count)
                    {
                        best_index = i;
                        best_count = count;
                    }
                }
                return best_index;
            }

            // Reproduce the per-candidate byte-resolution arithmetic in Address / Region terms. match is the scan hit
            // (already adjusted by the Pattern's `|` offset). Direct adds the signed walk-back; RipRelative reads the
            // disp32 the instruction spans under a fault guard and computes (next-IP + sign-extended disp). Both screen
            // the result through the plausible-userspace floor, so a faulted read or a crafted displacement is a miss,
            // never a hit at a near-null or kernel-range address (matching resolve_rip_relative's contract).
            [[nodiscard]] std::optional<std::uintptr_t> resolve_byte_candidate(std::uintptr_t match,
                                                                               const Candidate &candidate) noexcept
            {
                if (candidate.mode() == Mode::Direct)
                {
                    const std::uintptr_t resolved = match + static_cast<std::uintptr_t>(candidate.displacement());
                    if (!Memory::plausible_userspace_ptr(resolved))
                    {
                        return std::nullopt;
                    }
                    return resolved;
                }
                const std::uintptr_t displacement_address =
                    match + static_cast<std::uintptr_t>(candidate.displacement());
                const std::optional<std::int32_t> displacement = Memory::seh_read<std::int32_t>(displacement_address);
                if (!displacement)
                {
                    return std::nullopt;
                }
                const std::uintptr_t next_instruction =
                    match + static_cast<std::uintptr_t>(candidate.instruction_length());
                const std::uintptr_t resolved =
                    static_cast<std::uintptr_t>(static_cast<std::int64_t>(next_instruction) + *displacement);
                if (!Memory::plausible_userspace_ptr(resolved))
                {
                    return std::nullopt;
                }
                return resolved;
            }

            // One inline-hook prologue shape the fallback can rebuild and recover. patch_bytes is how many leading
            // prologue bytes the hook overwrites; jump_prefix is the AOB fragment that replaces them; decode recovers
            // the absolute target the rebuilt jump redirects to, so a match can be confirmed as a real hook rather than
            // a coincidental opcode collision.
            struct PrologueShape
            {
                std::size_t patch_bytes;
                std::string_view jump_prefix;
                std::optional<std::uintptr_t> (*decode)(std::uintptr_t) noexcept;
            };

            // Minimum fully-known tail bytes a rebuilt pattern must keep after the jump prefix. Ten literal bytes is
            // roughly two to four real instructions of context, which drops the false-positive rate of the generic
            // near-JMP shape to near zero on a multi-megabyte .text section.
            constexpr int PROLOGUE_MIN_TAIL_LITERALS = 10;

            // Inline-hook prologue shapes the fallback tries, in order. E9 is the five-byte near jump for a trampoline
            // within rel32 reach; the rest are the far-jump shapes emitted when the trampoline is beyond rel32 reach
            // (an FF 25 RIP-relative indirect jump through a pointer slot, the fourteen-byte FF 25 absolute form whose
            // disp32 is zero so the 8-byte target is inlined after the instruction, and the twelve-byte `mov rax,
            // imm64; jmp rax`). The literal opcode bytes make the shapes mutually exclusive at a real hook site, so the
            // try order only affects which is attempted first, never correctness; E9 leads because it is by far the
            // common case.
            constexpr std::array<PrologueShape, 4> PROLOGUE_SHAPES = {{
                {5, std::string_view{"E9 ?? ?? ?? ??"}, &detail::decode_e9_rel32},
                {6, std::string_view{"FF 25 ?? ?? ?? ??"}, &detail::decode_ff25_indirect},
                {14, std::string_view{"FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"}, &detail::decode_ff25_indirect},
                {12, std::string_view{"48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0"}, &detail::decode_mov_rax_imm64_jmp_rax},
            }};

            // Rebuild a Direct candidate's signature as one prologue shape: drop the patch_bytes leading prologue
            // tokens, prepend the shape's jump prefix, and keep the surviving tail token-exact. The jump prefix is
            // parsed through the shared constexpr DSL core so the prefix encoding has one source of truth. Returns
            // nullopt when the pattern is shorter than the patch or its literal tail is below the floor (the shape is
            // "not applicable" then). The rebuilt pattern carries offset 0: replacing the prologue dropped the original
            // `|` anchor, which the caller re-applies after the scan so a `|`-anchored candidate recovered here lands
            // on the same byte the direct scan would have.
            [[nodiscard]] std::optional<Scanner::CompiledPattern> build_rebuilt_prologue(const Pattern &original,
                                                                                         const PrologueShape &shape)
            {
                const std::size_t size = original.size();
                if (size < shape.patch_bytes)
                {
                    return std::nullopt;
                }
                const std::span<const std::byte> original_bytes = original.bytes();
                const std::span<const std::byte> original_mask = original.mask();
                int literal_tail = 0;
                for (std::size_t i = shape.patch_bytes; i < size; ++i)
                {
                    if (original_mask[i] == std::byte{0xFF})
                    {
                        ++literal_tail;
                    }
                }
                if (literal_tail < PROLOGUE_MIN_TAIL_LITERALS)
                {
                    return std::nullopt;
                }
                const detail::PatternParse prefix = detail::parse_pattern(shape.jump_prefix);
                if (prefix.status != detail::PatternStatus::Ok)
                {
                    // The shape prefixes are constant and well-formed; a parse failure would be a library defect, not
                    // user input, so fail this shape closed rather than scan a malformed pattern.
                    return std::nullopt;
                }
                Scanner::CompiledPattern rebuilt;
                rebuilt.bytes.reserve(prefix.buffer.length + (size - shape.patch_bytes));
                rebuilt.mask.reserve(prefix.buffer.length + (size - shape.patch_bytes));
                for (std::size_t i = 0; i < prefix.buffer.length; ++i)
                {
                    rebuilt.bytes.push_back(prefix.buffer.bytes[i]);
                    rebuilt.mask.push_back(prefix.buffer.mask[i]);
                }
                for (std::size_t i = shape.patch_bytes; i < size; ++i)
                {
                    rebuilt.bytes.push_back(original_bytes[i]);
                    rebuilt.mask.push_back(original_mask[i]);
                }
                rebuilt.offset = 0;
                rebuilt.compile_anchor();
                return rebuilt;
            }

            // Try one prologue shape for one Direct candidate: rebuild, require the rebuilt pattern to match exactly
            // once in the scope's executable pages (a hooked prologue is code), decode the jump to confirm a real
            // redirect, and resolve the anchored match. applicable becomes true once the rebuilt pattern is usable
            // (enough literal tail), independent of whether it then matches, so the caller can tell "no shape applied"
            // from "applied but missed".
            [[nodiscard]] std::optional<std::uintptr_t> try_prologue_shape(const Candidate &candidate,
                                                                           const PrologueShape &shape,
                                                                           Memory::ModuleRange range, bool &applicable)
            {
                const Pattern *pattern = candidate.pattern();
                if (pattern == nullptr)
                {
                    return std::nullopt;
                }
                const std::optional<Scanner::CompiledPattern> rebuilt = build_rebuilt_prologue(*pattern, shape);
                if (!rebuilt)
                {
                    return std::nullopt;
                }
                applicable = true;

                // Clear the per-thread incomplete flag, then count up to two occurrences over the executable pages. A
                // faulted region mid-scan makes the count a lower bound, so a single hit over an incomplete sweep does
                // not prove uniqueness; fail closed. More than one hit makes the rebuilt jump ambiguous; fail closed.
                Scanner::detail::scan_incomplete_flag() = false;
                const std::byte *first = Scanner::detail::scan_module_executable(*rebuilt, range, 1);
                if (first == nullptr)
                {
                    return std::nullopt;
                }
                const bool ambiguous = Scanner::detail::scan_module_executable(*rebuilt, range, 2) != nullptr;
                const bool incomplete = Scanner::detail::scan_incomplete_flag();
                if (ambiguous || incomplete)
                {
                    return std::nullopt;
                }

                const std::uintptr_t match = reinterpret_cast<std::uintptr_t>(first);
                const std::optional<std::uintptr_t> jump_target = shape.decode(match);
                if (!jump_target || !Memory::plausible_userspace_ptr(*jump_target) ||
                    !Scanner::detail::is_executable_address(*jump_target))
                {
                    // The matched bytes do not redirect to executable code, so this is a coincidental opcode collision,
                    // not a hooked prologue. The jump destination itself is intentionally NOT range-constrained: a
                    // sibling mod's trampoline is allocated outside every loaded module.
                    return std::nullopt;
                }

                const std::uintptr_t anchored = match + static_cast<std::uintptr_t>(pattern->offset());
                const std::optional<std::uintptr_t> resolved = resolve_byte_candidate(anchored, candidate);
                if (!resolved || !Memory::contains(range, *resolved))
                {
                    // Bound the recovered address to the requested scope, matching the normal byte path: a Direct
                    // walk-back must not resolve outside the range even when it is reached through prologue recovery.
                    return std::nullopt;
                }
                return resolved;
            }

            struct FallbackOutcome
            {
                std::optional<Hit> hit;
                // True until some Direct candidate yields a usable rebuilt pattern; lets resolve() report
                // PrologueFallbackNotApplicable only when a Direct row existed but its tail was too short.
                bool not_applicable = true;
                // True once any Direct candidate was a real rebuild target.
                bool had_direct = false;
            };

            // Run hooked-prologue recovery across the ordered ladder: for each Direct candidate, try each shape until
            // one uniquely recovers an executable target. Reproduces the v3 scan_candidates_hooked_prologue control
            // flow without the Logger coupling.
            [[nodiscard]] FallbackOutcome resolve_prologue_fallback(const ScanRequest &request,
                                                                    std::span<const std::size_t> order,
                                                                    Memory::ModuleRange range)
            {
                FallbackOutcome outcome;
                for (const std::size_t index : order)
                {
                    const Candidate &candidate = request.ladder[index];
                    if (candidate.mode() != Mode::Direct || candidate.pattern() == nullptr)
                    {
                        continue;
                    }
                    outcome.had_direct = true;
                    for (const PrologueShape &shape : PROLOGUE_SHAPES)
                    {
                        bool applicable = false;
                        const std::optional<std::uintptr_t> recovered =
                            try_prologue_shape(candidate, shape, range, applicable);
                        if (applicable)
                        {
                            outcome.not_applicable = false;
                        }
                        if (recovered)
                        {
                            outcome.hit = Hit{Address{*recovered}, candidate.name()};
                            return outcome;
                        }
                    }
                }
                return outcome;
            }
        } // namespace

        Candidate Candidate::direct(std::string name, Pattern pattern, std::ptrdiff_t walk_back)
        {
            Candidate candidate;
            candidate.m_name = std::move(name);
            candidate.m_mode = Mode::Direct;
            candidate.m_pattern = std::move(pattern);
            candidate.m_displacement = walk_back;
            return candidate;
        }

        Candidate Candidate::rip_relative(std::string name, Pattern pattern, std::ptrdiff_t displacement_at,
                                          std::size_t instruction_length)
        {
            Candidate candidate;
            candidate.m_name = std::move(name);
            candidate.m_mode = Mode::RipRelative;
            candidate.m_pattern = std::move(pattern);
            candidate.m_displacement = displacement_at;
            candidate.m_instruction_length = instruction_length;
            return candidate;
        }

        Candidate Candidate::rtti_vtable(std::string name, std::string mangled)
        {
            Candidate candidate;
            candidate.m_name = std::move(name);
            candidate.m_mode = Mode::RttiVtable;
            candidate.m_query = std::move(mangled);
            return candidate;
        }

        Candidate Candidate::string_xref(std::string name, std::string literal)
        {
            Candidate candidate;
            candidate.m_name = std::move(name);
            candidate.m_mode = Mode::StringXref;
            candidate.m_query = std::move(literal);
            return candidate;
        }

        std::size_t order_candidates(CandidateOrder order, std::span<const Candidate> ladder,
                                     std::span<std::size_t> out) noexcept
        {
            const std::size_t count = std::min(ladder.size(), out.size());
            if (order == CandidateOrder::AsDeclared)
            {
                for (std::size_t i = 0; i < count; ++i)
                {
                    out[i] = i;
                }
                return count;
            }

            // UniqueFirst: three stable passes over the declared order. Every candidate falls into exactly one pass, so
            // the result is a permutation of [0, count).
            std::size_t written = 0;
            const auto emit = [&](auto predicate)
            {
                for (std::size_t i = 0; i < ladder.size() && written < count; ++i)
                {
                    if (predicate(ladder[i]))
                    {
                        out[written] = i;
                        ++written;
                    }
                }
            };
            const auto is_byte_mode = [](const Candidate &candidate)
            { return candidate.mode() == Mode::Direct || candidate.mode() == Mode::RipRelative; };
            const auto is_anchored_byte = [&](const Candidate &candidate)
            {
                const Pattern *pattern = candidate.pattern();
                return is_byte_mode(candidate) && pattern != nullptr && pattern->has_anchor();
            };

            // Pass 1: the unique-only text tiers, which fail closed on ambiguity by construction.
            emit([](const Candidate &candidate)
                 { return candidate.mode() == Mode::RttiVtable || candidate.mode() == Mode::StringXref; });
            // Pass 2: anchored byte patterns (a fully-known rarest byte makes the scan far more selective).
            emit([&](const Candidate &candidate) { return is_anchored_byte(candidate); });
            // Pass 3: the remaining byte patterns (no fully-known byte to anchor on).
            emit([&](const Candidate &candidate) { return is_byte_mode(candidate) && !is_anchored_byte(candidate); });
            return written;
        }

        ScanRequest borrow(std::span<const Candidate> ladder, std::string_view label, Region scope,
                           bool prologue_fallback, bool require_unique, CandidateOrder order) noexcept
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

        Result<Hit> resolve(const ScanRequest &request)
        {
            if (request.ladder.empty())
            {
                return std::unexpected(Error{ErrorCode::EmptyCandidates, "scan::resolve"});
            }
            const Memory::ModuleRange range = to_module_range(request.scope);
            if (!range.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::resolve"});
            }

            // Lay out the try order once. The haystack histogram is sampled lazily on the first byte candidate and
            // shared across every byte candidate in the ladder, since they all scan the same scope.
            std::vector<std::size_t> order(request.ladder.size());
            const std::size_t ordered_count = order_candidates(request.order, request.ladder, order);
            std::optional<HaystackHistogram> histogram;

            for (std::size_t k = 0; k < ordered_count; ++k)
            {
                const Candidate &candidate = request.ladder[order[k]];

                if (candidate.mode() == Mode::RttiVtable)
                {
                    const std::optional<std::uintptr_t> vtable = Rtti::vtable_for_type(candidate.query(), range);
                    if (vtable && Memory::contains(range, *vtable))
                    {
                        return Hit{Address{*vtable}, candidate.name()};
                    }
                    continue;
                }
                if (candidate.mode() == Mode::StringXref)
                {
                    // Designated init so a future StringRefQuery field reorder cannot silently misassign a facet; the
                    // remaining facets keep their legacy defaults (UTF-8, terminator-required, referencing-instruction,
                    // narrow).
                    const Scanner::StringRefQuery query{.text = candidate.query()};
                    const std::expected<std::uintptr_t, Scanner::StringXrefError> site =
                        Scanner::find_string_xref(query, range);
                    if (site && Memory::contains(range, *site))
                    {
                        return Hit{Address{*site}, candidate.name()};
                    }
                    continue;
                }

                // Byte tiers (Direct / RipRelative).
                const Pattern *pattern = candidate.pattern();
                if (pattern == nullptr)
                {
                    // Unreachable through the factories (a byte candidate always carries a pattern); skip defensively.
                    continue;
                }
                if (!histogram)
                {
                    histogram = sample_haystack(request.scope);
                }
                const std::size_t anchor = choose_scan_anchor(*pattern, *histogram);
                const Scanner::CompiledPattern compiled = to_compiled(*pattern, anchor);

                Scanner::detail::scan_incomplete_flag() = false;
                const std::byte *first = Scanner::detail::scan_module_readable(compiled, range, 1);
                bool incomplete = Scanner::detail::scan_incomplete_flag();
                if (first == nullptr)
                {
                    continue;
                }
                const bool ambiguous =
                    request.require_unique && Scanner::detail::scan_module_readable(compiled, range, 2) != nullptr;
                incomplete = incomplete || Scanner::detail::scan_incomplete_flag();
                if (incomplete)
                {
                    // A faulted region makes the occurrence count a lower bound. A hidden earlier match or duplicate
                    // could live in skipped bytes, so accepting this candidate would turn a race into a wrong address.
                    continue;
                }
                if (ambiguous)
                {
                    // Ambiguous in scope: the lowest-address match is not provably the intended target, so fall through
                    // to the next candidate rather than commit to an arbitrary site.
                    continue;
                }
                const std::optional<std::uintptr_t> resolved =
                    resolve_byte_candidate(reinterpret_cast<std::uintptr_t>(first), candidate);
                if (!resolved || !Memory::contains(range, *resolved))
                {
                    // A RipRelative displacement can resolve outside the scanned scope (e.g. an import thunk in another
                    // module); reject it here so the cascade falls through instead of committing out of scope.
                    continue;
                }
                return Hit{Address{*resolved}, candidate.name()};
            }

            if (request.prologue_fallback)
            {
                const FallbackOutcome fallback = resolve_prologue_fallback(
                    request, std::span<const std::size_t>{order.data(), ordered_count}, range);
                if (fallback.hit)
                {
                    return *fallback.hit;
                }
                if (fallback.had_direct && fallback.not_applicable)
                {
                    // A Direct candidate existed to rebuild, but its literal tail was too short for any shape. This is
                    // a distinct diagnostic from a plain miss (a name/string/RipRelative-only ladder has no Direct
                    // row).
                    return std::unexpected(Error{ErrorCode::PrologueFallbackNotApplicable, "scan::resolve"});
                }
            }

            return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve"});
        }

        std::vector<Result<Hit>> resolve_batch(std::span<const ScanRequest> requests, std::size_t max_workers) noexcept
        {
            try
            {
                return detail::run_fork_join<ScanRequest, Result<Hit>>(
                    requests, max_workers,
                    [](const ScanRequest &request) -> Result<Hit>
                    {
                        try
                        {
                            return resolve(request);
                        }
                        catch (const std::bad_alloc &)
                        {
                            return std::unexpected(Error{ErrorCode::OutOfMemory, "scan::resolve_batch"});
                        }
                    },
                    [](const ScanRequest &) noexcept -> Result<Hit>
                    { return std::unexpected(Error{ErrorCode::NoMatch, "scan::resolve_batch"}); });
            }
            catch (const std::bad_alloc &)
            {
                return {};
            }
            catch (...)
            {
                return {};
            }
        }

        Result<Address> scan(const Pattern &pattern, Region scope) noexcept
        {
            const Memory::ModuleRange range = to_module_range(scope);
            if (!range.valid())
            {
                return std::unexpected(Error{ErrorCode::InvalidRange, "scan::scan"});
            }
            try
            {
                const HaystackHistogram histogram = sample_haystack(scope);
                const std::size_t anchor = choose_scan_anchor(pattern, histogram);
                const Scanner::CompiledPattern compiled = to_compiled(pattern, anchor);
                Scanner::detail::scan_incomplete_flag() = false;
                const std::byte *match = Scanner::detail::scan_module_readable(compiled, range, 1);
                if (match == nullptr)
                {
                    return std::unexpected(Error{ErrorCode::NoMatch, "scan::scan"});
                }
                if (Scanner::detail::scan_incomplete_flag())
                {
                    return std::unexpected(Error{ErrorCode::NoMatch, "scan::scan"});
                }
                return Address{reinterpret_cast<std::uintptr_t>(match)};
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "scan::scan"});
            }
        }

        const std::byte *unchecked::find_pattern(Region region, const Pattern &pattern) noexcept
        {
            if (region.base.raw() == 0 || region.size == 0)
            {
                return nullptr;
            }
            try
            {
                // The raw primitive does no page filtering, so the caller owns readability; it also does not consult
                // the haystack histogram (that override accelerates the page-gated scan), using the Pattern's
                // compile-time anchor directly.
                const std::size_t anchor = pattern.has_anchor() ? pattern.anchor_index() : pattern.size();
                const Scanner::CompiledPattern compiled = to_compiled(pattern, anchor);
                return Scanner::find_pattern(region.base.ptr<const std::byte>(), region.size, compiled);
            }
            catch (const std::bad_alloc &)
            {
                return nullptr;
            }
        }

    } // namespace scan
} // namespace DetourModKit
