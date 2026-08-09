/**
 * @file internal/scan_pages.cpp
 * @brief Page-gated AOB scanning: the VirtualQuery region walk, the per-region TOCTOU fault guard, the committed-window
 *        collector, and the executable-address / executable-range predicates.
 * @details Wraps the raw matcher in the OS page map so a scan over arbitrary process memory reads only committed pages
 *          of the requested protection class. Incomplete-scan state rides on the MatchResult return value rather than a
 *          thread-local side channel, so concurrent scans cannot clobber each other's fault state. The Windows
 *          page-protection masks stay private to this TU.
 */

#include "internal/scan_pages.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/memory_fault.hpp"
#include "internal/scan_fault_seam.hpp"

#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h> // __movsb -- forward, ASan-safe foreign-memory copy
#endif

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        // The two exclusion sets a match is tested against: the engine's unconditional guarantee that a scan never
        // returns the compiled pattern's own buffers, and whatever query storage the caller declared. Keeping them
        // separate lets the floor guarantee hold even for a caller that passes no exclusions at all.
        struct ExclusionSet
        {
            const detail::ScanExclusions &engine;
            const detail::ScanExclusions *caller;

            [[nodiscard]] bool excludes(std::uintptr_t lo, std::uintptr_t hi) const noexcept
            {
                return engine.overlaps(lo, hi) || (caller != nullptr && caller->overlaps(lo, hi));
            }
        };

        // Running occurrence state for one page walk. Shared across regions so the Nth match and the (N+1)th detection
        // come from a single traversal.
        struct ScanTally
        {
            std::size_t seen = 0;
            const std::byte *nth_point = nullptr;
            Region nth_span{};
            scan::WinningEvidence nth_evidence{};
            detail::InstructionSnapshot nth_instruction{};
        };

        // MSVC ASan intercepts libc copies from this process's foreign/poisoned memory. Keep the copy inline so a valid
        // scan of instrumented storage does not become a false overflow report.
        void copy_foreign_bytes(std::byte *destination, const std::byte *source, std::size_t size) noexcept
        {
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
            __movsb(reinterpret_cast<unsigned char *>(destination), reinterpret_cast<const unsigned char *>(source),
                    size);
#else
            std::memcpy(destination, source, size);
#endif
        }

        // Copy the literal bytes of [start, end) out of the live image. Called only from inside the TOCTOU fault guard,
        // while the region is still proven readable: the match pointers must not outlive that window, so the bytes are
        // taken as a value here rather than re-read later from a span that a concurrent unmap may have invalidated.
        // An over-long span yields truncated evidence with no bytes at all, because a captured prefix would compare
        // equal against a prefix baseline and quietly authorize a mutation on partial evidence.
        [[nodiscard]] scan::WinningEvidence capture_winning_evidence(const std::byte *start,
                                                                     const std::byte *end) noexcept
        {
            scan::WinningEvidence evidence{};
            if (start == nullptr || end == nullptr || end <= start)
            {
                return evidence;
            }
            const auto span_length = static_cast<std::size_t>(end - start);
            if (span_length > scan::MAX_MUTATION_WITNESS_BYTES)
            {
                evidence.truncated = true;
                return evidence;
            }
            copy_foreign_bytes(evidence.bytes.data(), start, span_length);
            evidence.length = static_cast<std::uint16_t>(span_length);
            return evidence;
        }

        [[nodiscard]] detail::InstructionSnapshot
        capture_instruction_snapshot(const std::byte *start, const std::byte *end, const std::byte *point,
                                     std::uintptr_t capture_limit, std::uint8_t requested_length,
                                     const scan::WinningEvidence &evidence) noexcept
        {
            detail::InstructionSnapshot snapshot{};
            if (requested_length == 0 || requested_length > scan::MAX_X86_INSTRUCTION_LENGTH || start == nullptr ||
                end == nullptr || point == nullptr || point < start || point > end)
            {
                return snapshot;
            }
            const auto point_offset = static_cast<std::size_t>(point - start);
            const auto span_length = static_cast<std::size_t>(end - start);
            const std::uintptr_t point_address = reinterpret_cast<std::uintptr_t>(point);
            if (point_offset > span_length || point_address >= capture_limit ||
                requested_length > capture_limit - point_address)
            {
                return snapshot;
            }

            if (evidence.present())
            {
                const std::size_t evidenced_length = span_length - point_offset;
                const std::size_t copy_length =
                    requested_length < evidenced_length ? requested_length : evidenced_length;
                copy_foreign_bytes(snapshot.bytes.data(), evidence.bytes.data() + point_offset, copy_length);
                if (copy_length < requested_length)
                {
                    copy_foreign_bytes(snapshot.bytes.data() + copy_length, point + copy_length,
                                       requested_length - copy_length);
                }
            }
            else
            {
                copy_foreign_bytes(snapshot.bytes.data(), point, requested_length);
            }
            snapshot.length = requested_length;
            return snapshot;
        }

        // Scan one protection-gated region, tallying every counted, non-excluded match. Returns true once the tally
        // reaches @p cap, which tells the caller to stop walking. This is the body the TOCTOU fault guard wraps (see
        // scan_region_guarded): it performs the unguarded find_pattern_raw reads across [region_start, +scan_size).
        //
        // count_floor is the address below which matches were already tallied by an earlier region in this contiguous
        // accepted run. When a region is back-extended over a protection split, it re-reads the tail of the previous
        // region to catch a match straddling the boundary; a match that ended inside that tail (end <= count_floor) was
        // already counted there, so it is skipped here. Comparing the match's true end (RawMatch::end), not a fixed
        // pattern length, is what keeps this correct for a variable-length bounded-jump match, where a fixed-length
        // overlap would double-count a short match near the boundary.
        bool scan_region_for_match(const std::byte *region_start, std::size_t scan_size,
                                   const detail::EnginePattern &pattern, const ExclusionSet &exclusions,
                                   std::uintptr_t count_floor, std::size_t target, std::size_t cap, bool capture,
                                   std::uintptr_t snapshot_limit, std::uint8_t instruction_snapshot_length,
                                   ScanTally &tally, bool &out_budget_exhausted) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            // Inside the guard's frame, so an armed address that the declared span does not cover proves the guard
            // screens the faulting address rather than only the exception class.
            detail::fire_scan_fault_seam_for_test(detail::g_scan_region_fault_for_test);
#endif
            // One SegmentedScanBudget stays live across every find_pattern_raw suffix call below. A bounded-jump sweep
            // whose per-position or region-wide backtracking budget was spent leaves the occurrence count a lower
            // bound, exactly like a faulted-region skip. The flag is meaningful even when no match is found: a
            // truncated no-match is not a proven absence.
            detail::SegmentedScanBudget segmented_budget{};
            detail::RawMatch match = detail::find_pattern_raw(region_start, scan_size, pattern, &segmented_budget);
            out_budget_exhausted = match.budget_exhausted;
            while (match.start != nullptr)
            {
                const auto match_addr = reinterpret_cast<std::uintptr_t>(match.start);
                const auto match_end = reinterpret_cast<std::uintptr_t>(match.end);
                // The match spans [match_addr, match_end); using the true end (not a fixed pattern length) keeps both
                // the exclusion test and the boundary de-duplication exact for a bounded-jump match.
                const bool excluded = exclusions.excludes(match_addr, match_end);
                const bool already_counted = match_end <= count_floor;
                if (!excluded && !already_counted)
                {
                    ++tally.seen;
                    if (tally.seen == target)
                    {
                        tally.nth_point = match.point;
                        const std::uintptr_t span_start = reinterpret_cast<std::uintptr_t>(match.start);
                        const std::uintptr_t span_end = reinterpret_cast<std::uintptr_t>(match.end);
                        tally.nth_span = Region{Address{span_start}, static_cast<std::size_t>(span_end - span_start)};
                        if (capture)
                        {
                            tally.nth_evidence = capture_winning_evidence(match.start, match.end);
                        }
                        if (instruction_snapshot_length != 0)
                        {
                            tally.nth_instruction =
                                capture_instruction_snapshot(match.start, match.end, match.point, snapshot_limit,
                                                             instruction_snapshot_length, tally.nth_evidence);
                        }
                    }
                    if (tally.seen >= cap)
                    {
                        return true;
                    }
                }

                // Continue scanning past the current match START (not its variable end).
                const std::size_t consumed = static_cast<std::size_t>(match.start - region_start) + 1;
                if (consumed >= scan_size)
                {
                    break;
                }
                match = detail::find_pattern_raw(match.start + 1, scan_size - consumed, pattern, &segmented_budget);
                out_budget_exhausted = out_budget_exhausted || match.budget_exhausted;
            }
            return false;
        }

        // Region-granular TOCTOU fault guard around scan_region_for_match. The caller's per-region VirtualQuery only
        // proves the region was committed and readable at gate time; a concurrent decommit / reprotect before these
        // unguarded reads complete would otherwise fault the host. Both arms claim a fault only inside the exact span
        // this sweep is permitted to read, [span_lo, capture_limit): on MSVC through
        // detail::guarded_range_fault_filter, on MinGW x64 through the same process-wide vectored read guard the
        // guarded_read paths use, armed over that span. An access-class fault OUTSIDE it is an unrelated defect rather
        // than the concurrent unmap this guard exists to absorb, so it reaches the host's handlers instead of being
        // recorded as a faulted region. A 32-bit build is rejected outright by the architecture gate in defines.hpp,
        // so only these two x64 arms exist.
        bool scan_region_guarded(const std::byte *region_start, std::size_t scan_size,
                                 const detail::EnginePattern &pattern, const ExclusionSet &exclusions,
                                 std::uintptr_t count_floor, std::size_t target, std::size_t cap, bool capture,
                                 std::uintptr_t snapshot_limit, std::uint8_t instruction_snapshot_length,
                                 ScanTally &tally, bool &out_faulted, bool &out_budget_exhausted) noexcept
        {
            out_faulted = false;
            const std::uintptr_t span_lo = reinterpret_cast<std::uintptr_t>(region_start);
            const std::uintptr_t scan_hi = span_lo + scan_size;
            std::uintptr_t capture_limit = scan_hi;
            if (instruction_snapshot_length != 0 && capture_limit < snapshot_limit)
            {
                const std::uintptr_t available = snapshot_limit - capture_limit;
                const std::uintptr_t extension =
                    instruction_snapshot_length < available ? instruction_snapshot_length : available;
                capture_limit += extension;
            }
            // A faulted region is treated as skipped, not partially scanned: matches observed before the fault cannot
            // be trusted for occurrence accounting because unreadable tail bytes may hide additional matches. The skip
            // already forces the scan incomplete, so any partial budget-exhaustion state from the aborted sweep is
            // moot and is cleared so it is not double-counted.
            const ScanTally original_tally = tally;
#ifdef _MSC_VER
            __try
            {
                return scan_region_for_match(region_start, scan_size, pattern, exclusions, count_floor, target, cap,
                                             capture, capture_limit, instruction_snapshot_length, tally,
                                             out_budget_exhausted);
            }
            __except (detail::guarded_range_fault_filter(GetExceptionInformation(), span_lo, capture_limit))
            {
                tally = original_tally;
                out_faulted = true;
                out_budget_exhausted = false;
                return false;
            }
#elif defined(_WIN64)
            // MinGW x64: route the sweep through the same vectored fault guard as the foreign-read primitives. The
            // armed range includes the pattern window plus the bounded, scope-clamped instruction-snapshot tail.
            struct ScanContext
            {
                const std::byte *region_start;
                std::size_t scan_size;
                const detail::EnginePattern *pattern;
                const ExclusionSet *exclusions;
                std::uintptr_t count_floor;
                std::size_t target;
                std::size_t cap;
                bool capture;
                std::uintptr_t snapshot_limit;
                std::uint8_t instruction_snapshot_length;
                ScanTally *tally;
                bool *budget_exhausted;
                bool cap_reached;
            } scan_ctx{region_start,  scan_size,
                       &pattern,      &exclusions,
                       count_floor,   target,
                       cap,           capture,
                       capture_limit, instruction_snapshot_length,
                       &tally,        &out_budget_exhausted,
                       false};

            const auto run_scan = [](void *opaque) noexcept -> void
            {
                auto *context = static_cast<ScanContext *>(opaque);
                context->cap_reached = scan_region_for_match(
                    context->region_start, context->scan_size, *context->pattern, *context->exclusions,
                    context->count_floor, context->target, context->cap, context->capture, context->snapshot_limit,
                    context->instruction_snapshot_length, *context->tally, *context->budget_exhausted);
            };

            if (detail::run_guarded_region(span_lo, capture_limit, run_scan, &scan_ctx))
            {
                return scan_ctx.cap_reached;
            }
            tally = original_tally;
            out_faulted = true;
            out_budget_exhausted = false;
            return false;
#endif
        }

        // Region-walking AOB scan shared by the whole-process and module-scoped entry points. Walks the committed
        // regions of [window_lo, window_hi) via VirtualQuery and runs the per-region scan (behind the fault guard)
        // against every region whose base protection is present in accept_mask. The whole-process scanners pass
        // [0, UINTPTR_MAX); the module-scoped scan passes the image's [base, end).
        //
        // Guard, no-access, and uncommitted regions are always skipped: PAGE_GUARD raises STATUS_GUARD_PAGE_VIOLATION
        // on the first touch and PAGE_NOACCESS faults even for reads, so neither is safe to dereference. The Windows
        // base protections are mutually exclusive single bits, so a bitwise-AND against a mask of the acceptable bases
        // is a sound membership test. PAGE_GUARD is a modifier bit OR-ed onto a base value, so it must be excluded
        // separately or it would satisfy the mask and be scanned.
        //
        // To find a signature that straddles a protection split -- two adjacent accepted regions VirtualQuery reports
        // separately because their base protections differ (a sibling VirtualProtect carving part of .text into
        // PAGE_EXECUTE_READWRITE is the canonical case) -- each accepted region's scan is extended back by up to
        // max_match_length() - 1 bytes into the contiguous run of already-accepted regions it abuts, bounded by the run
        // start so it never reads past the bytes the per-region gate proved readable. A match wholly inside the
        // previous region is not re-counted: the region's true start is passed as a count floor, and only a match whose
        // end reaches past it is counted. The floor, not the carry width, is what prevents a double count, which is why
        // a variable-length bounded-jump match stays correctly counted across the split.
        detail::MatchResult scan_regions_filtered(const detail::EnginePattern &pattern, const detail::ScanQuery &query,
                                                  DWORD accept_mask, std::uintptr_t window_lo,
                                                  std::uintptr_t window_hi) noexcept
        {
            ScanTally tally;

            // The compiled pattern's own bytes and mask buffers live in readable heap memory, so a readable sweep would
            // otherwise match the needle against itself and could return the query's storage instead of the intended
            // target. This floor guarantee holds regardless of what the caller declared; caller-owned copies of the
            // query ride query.exclusions on top of it.
            //
            // When evidence capture is on, the tally buffer joins that floor for the same reason and is strictly worse
            // if left out: it holds a verbatim copy of a MATCHED span, so once one match is captured the sweep would
            // count that copy as a further occurrence.
            detail::ScanExclusions engine_owned;
            detail::add_engine_pattern_storage(engine_owned, pattern);
            if (query.capture_evidence)
            {
                engine_owned.add(reinterpret_cast<std::uintptr_t>(tally.nth_evidence.bytes.data()),
                                 tally.nth_evidence.bytes.size());
            }
            if (query.instruction_snapshot_length != 0)
            {
                engine_owned.add(reinterpret_cast<std::uintptr_t>(tally.nth_instruction.bytes.data()),
                                 tally.nth_instruction.bytes.size());
            }
            const ExclusionSet exclusions{engine_owned, query.exclusions};

            const std::size_t target = query.occurrence;
            const std::size_t cap =
                query.count_beyond && target != std::numeric_limits<std::size_t>::max() ? target + 1 : target;

            std::size_t faulted_regions = 0;
            bool budget_exhausted_total = false;
            bool cap_reached = false;
            MEMORY_BASIC_INFORMATION mbi{};
            std::uintptr_t addr = window_lo;

            // Contiguous-accepted-run tracking for the cross-boundary overlap (see the function comment).
            // prev_accept_hi is the end of the previous accepted region; run_lo is the start of the run of contiguous
            // accepted regions the current region belongs to. A gap (a skipped, guarded, or non-readable region) breaks
            // the run because the bytes across it are not proven readable.
            bool prev_accepted = false;
            std::uintptr_t prev_accept_hi = 0;
            std::uintptr_t run_lo = 0;

            while (!cap_reached && addr < window_hi && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            {
                const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
                const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t region_end = region_base + mbi.RegionSize;

                // Clamp the region to the requested window so a region that straddles window_lo / window_hi is
                // inspected only where it intersects. For a whole-process sweep the clamp is a no-op; for a
                // module-scoped sweep this is what keeps the scan inside [base, end) even when a VirtualQuery region
                // extends past it.
                const std::uintptr_t scan_lo = region_base < window_lo ? window_lo : region_base;
                const std::uintptr_t scan_hi = region_end > window_hi ? window_hi : region_end;

                if (mbi.State == MEM_COMMIT && (mbi.Protect & accept_mask) != 0 && !protection_unsafe &&
                    scan_hi > scan_lo)
                {
                    // Continue the accepted run only when this region begins exactly where the previous accepted one
                    // ended; otherwise restart it here. Done before computing the overlap so run_lo reflects the run
                    // scan_lo joins.
                    if (!prev_accepted || prev_accept_hi != scan_lo)
                    {
                        run_lo = scan_lo;
                    }

                    std::uintptr_t effective_scan_lo = scan_lo;
                    const std::size_t match_span = pattern.max_match_length();
                    if (match_span > 1 && scan_lo > run_lo)
                    {
                        const std::uintptr_t max_overlap = static_cast<std::uintptr_t>(match_span - 1);
                        const std::uintptr_t available = scan_lo - run_lo;
                        effective_scan_lo = scan_lo - ((max_overlap < available) ? max_overlap : available);
                    }

                    const std::size_t scan_size = static_cast<std::size_t>(scan_hi - effective_scan_lo);
                    bool region_faulted = false;
                    if (scan_size >= pattern.size())
                    {
                        const auto *region_start = reinterpret_cast<const std::byte *>(effective_scan_lo);

                        // The protection gate above proved the region readable at gate time; scan_region_guarded
                        // backstops a concurrent decommit / reprotect that could fault the read after the gate. scan_lo
                        // is the count floor: matches that ended before it were already tallied by the previous region.
                        bool region_budget_exhausted = false;
                        cap_reached =
                            scan_region_guarded(region_start, scan_size, pattern, exclusions, scan_lo, target, cap,
                                                query.capture_evidence, window_hi, query.instruction_snapshot_length,
                                                tally, region_faulted, region_budget_exhausted);
                        // A spent bounded-jump backtracking budget makes any occurrence count a lower bound, exactly
                        // like a skipped faulted region, so it feeds the same incomplete signal.
                        budget_exhausted_total = budget_exhausted_total || region_budget_exhausted;
                        if (region_faulted)
                        {
                            ++faulted_regions;
                        }
                    }

                    // A faulted region ends the run as surely as a gap does. Its bytes were abandoned mid-read, so the
                    // next region must not back-extend into them: that overlap would fault as well and cost a second,
                    // fully readable region its entire sweep.
                    prev_accepted = !region_faulted;
                    prev_accept_hi = scan_hi;
                }
                else
                {
                    prev_accepted = false;
                }

                assert(region_end > addr && "VirtualQuery returned a non-advancing region");
                if (region_end <= addr)
                {
                    break; // Overflow guard.
                }
                addr = region_end;
            }

            if (faulted_regions != 0)
            {
                // Best-effort diagnosis only; the sweep already skipped each faulted region and continued, and the
                // skipped bytes are what the incomplete flag below makes the caller fail closed on.
                try
                {
                    (void)log().try_log(
                        LogLevel::Debug,
                        "Scanner: skipped {} region(s) that faulted mid-scan (concurrent decommit/reprotect).",
                        faulted_regions);
                }
                catch (...)
                {
                }

                // The dispatcher is lazy and can allocate on first use, so diagnostics must never change the result.
                try
                {
                    diagnostics::scanner_faults().emit_safe(diagnostics::ScannerFaultEvent{
                        .faulted_regions = faulted_regions, .window_low = window_lo, .window_high = window_hi});
                }
                catch (...)
                {
                }
            }
            return detail::MatchResult{tally.nth_point,       tally.nth_span, tally.nth_evidence,
                                       tally.nth_instruction, tally.seen,     faulted_regions > 0,
                                       budget_exhausted_total};
        }

        // Base protections accepted by the executable-only sweeps: the three page variants that grant execute *and*
        // read. Bare PAGE_EXECUTE (execute without a read bit) is excluded because dereferencing it raises an access
        // violation; PAGE_GUARD / PAGE_NOACCESS are filtered separately inside scan_regions_filtered.
        constexpr DWORD EXECUTABLE_PAGE_FLAGS = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        // Base protections accepted by the readable sweep: the executable-readable set plus the non-executable
        // readable pages (.rdata / .data and read-only heaps). This reaches C++ vtables, RTTI type descriptors, and
        // other read-only metadata the executable-only sweep cannot see.
        constexpr DWORD READABLE_PAGE_FLAGS = EXECUTABLE_PAGE_FLAGS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;

        // Shared precondition for every page-gated entry point.
        [[nodiscard]] bool query_is_scannable(const detail::EnginePattern &pattern,
                                              const detail::ScanQuery &query) noexcept
        {
            return !pattern.empty() && query.occurrence != 0;
        }

        // Region walks a scope may cross while still counting as one caller-named allocation. A scope that needs more
        // than this is not something the caller enumerated; it is a sweep of whatever happens to be mapped.
        constexpr std::size_t MAX_CONFINED_REGIONS = 64;

        // True when [range.base, range.end) lies inside a single reserved allocation. VirtualAlloc hands out one
        // AllocationBase per reservation and VirtualQuery splits it into regions as protections diverge, so a constant
        // AllocationBase across the walk is exactly "the caller named one buffer". A whole-process window fails on the
        // first region boundary that changes it.
        [[nodiscard]] bool span_is_single_allocation(detail::ModuleSpan range) noexcept
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(range.base), &mbi, sizeof(mbi)) == 0 ||
                mbi.AllocationBase == nullptr)
            {
                return false;
            }
            const LPVOID allocation_base = mbi.AllocationBase;

            std::uintptr_t cursor = range.base;
            for (std::size_t visited = 0; visited < MAX_CONFINED_REGIONS; ++visited)
            {
                if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0 ||
                    mbi.AllocationBase != allocation_base)
                {
                    return false;
                }
                const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                if (mbi.RegionSize == 0 || region_base > UINTPTR_MAX - mbi.RegionSize)
                {
                    return false;
                }
                const std::uintptr_t region_end = region_base + mbi.RegionSize;
                if (region_end <= cursor)
                {
                    return false;
                }
                if (region_end >= range.end)
                {
                    return true;
                }
                cursor = region_end;
            }
            return false;
        }
    } // anonymous namespace

    bool detail::readable_scan_is_authoritative(detail::ModuleSpan range, scan::Pages pages,
                                                std::span<const Region> exclusions) noexcept
    {
        if (pages != scan::Pages::Readable || !exclusions.empty())
        {
            return true;
        }
        const ModuleSpan image = module_span(memory::module_of(Address{range.base}));
        if (image.valid() && range.base >= image.base && range.end <= image.end)
        {
            return true;
        }
        return span_is_single_allocation(range);
    }

    detail::MatchResult detail::scan_module_executable(const detail::EnginePattern &pattern, detail::ModuleSpan range,
                                                       const detail::ScanQuery &query) noexcept
    {
        // EXECUTABLE_PAGE_FLAGS confines the match to code, so a data-page hit cannot pose as an instruction site.
        if (!query_is_scannable(pattern, query) || !range.valid())
        {
            return MatchResult{};
        }
        return scan_regions_filtered(pattern, query, EXECUTABLE_PAGE_FLAGS, range.base, range.end);
    }

    detail::MatchResult detail::scan_module_readable(const detail::EnginePattern &pattern, detail::ModuleSpan range,
                                                     const detail::ScanQuery &query) noexcept
    {
        // READABLE_PAGE_FLAGS lets one pass cover both .text and .rdata / .data candidates.
        if (!query_is_scannable(pattern, query) || !range.valid())
        {
            return MatchResult{};
        }
        return scan_regions_filtered(pattern, query, READABLE_PAGE_FLAGS, range.base, range.end);
    }

    detail::MatchResult detail::scan_executable_regions(const detail::EnginePattern &pattern,
                                                        const detail::ScanQuery &query) noexcept
    {
        if (!query_is_scannable(pattern, query))
        {
            return MatchResult{};
        }
        // The window spans the entire user address space, so the clamp in scan_regions_filtered is a no-op and the walk
        // stops only when VirtualQuery runs off the end of the address space.
        return scan_regions_filtered(pattern, query, EXECUTABLE_PAGE_FLAGS, 0, UINTPTR_MAX);
    }

    detail::MatchResult detail::scan_readable_regions(const detail::EnginePattern &pattern,
                                                      const detail::ScanQuery &query) noexcept
    {
        if (!query_is_scannable(pattern, query))
        {
            return MatchResult{};
        }
        return scan_regions_filtered(pattern, query, READABLE_PAGE_FLAGS, 0, UINTPTR_MAX);
    }

    detail::MatchResult detail::scan_module_pages(const detail::EnginePattern &pattern, detail::ModuleSpan range,
                                                  scan::Pages pages, const detail::ScanQuery &query) noexcept
    {
        // An out-of-range enum value must not silently widen to readable pages, so reject it as an empty result.
        switch (pages)
        {
        case scan::Pages::Readable:
            return scan_module_readable(pattern, range, query);
        case scan::Pages::Executable:
            return scan_module_executable(pattern, range, query);
        }
        return MatchResult{};
    }

    // Centralizes the executable-page protection gate for out-of-TU callers (the string-xref backend): one VirtualQuery
    // walk over [range.base, range.end) that returns each committed, execute-readable region clamped to the range,
    // using the identical mask scan_module_executable applies. The per-region gate guarantees the window is readable at
    // gate time; the caller still wraps its reads in a fault guard so a concurrent decommit / reprotect between gate
    // and read cannot fault the host.
    std::vector<detail::ExecutableWindow> detail::collect_executable_windows(detail::ModuleSpan range)
    {
        std::vector<ExecutableWindow> windows;
        if (!range.valid())
        {
            return windows;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        std::uintptr_t addr = range.base;
        while (addr < range.end && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        {
            const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
            const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t region_end = region_base + mbi.RegionSize;
            const std::uintptr_t scan_lo = region_base < range.base ? range.base : region_base;
            const std::uintptr_t scan_hi = region_end > range.end ? range.end : region_end;

            if (mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PAGE_FLAGS) != 0 && !protection_unsafe &&
                scan_hi > scan_lo)
            {
                windows.push_back(ExecutableWindow{scan_lo, static_cast<std::size_t>(scan_hi - scan_lo)});
            }

            if (region_end <= addr)
            {
                break; // Overflow guard, mirroring scan_regions_filtered.
            }
            addr = region_end;
        }
        return windows;
    }

    // Single-address sibling of the executable-page gate scan_regions_filtered applies per region, so the
    // prologue-recovery fallback can vet a decoded jump destination without re-deriving the Windows page masks or
    // constraining it to a loaded module (a sibling mod's trampoline is VirtualAlloc'd outside every image).
    bool detail::is_executable_address(std::uintptr_t address) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        {
            return false;
        }
        const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
        return mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PAGE_FLAGS) != 0 && !protection_unsafe;
    }

    bool detail::is_executable_range(std::uintptr_t address, std::size_t size) noexcept
    {
        if (address == 0 || size == 0 || size > UINTPTR_MAX - address)
        {
            return false;
        }

        const std::uintptr_t end = address + size;
        std::uintptr_t cursor = address;
        while (cursor < end)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0)
            {
                return false;
            }

            const std::uintptr_t region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            if (mbi.RegionSize == 0 || region_base > UINTPTR_MAX - mbi.RegionSize)
            {
                return false;
            }
            const std::uintptr_t region_end = region_base + mbi.RegionSize;
            const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
            if (cursor < region_base || mbi.State != MEM_COMMIT || (mbi.Protect & EXECUTABLE_PAGE_FLAGS) == 0 ||
                protection_unsafe || region_end <= cursor)
            {
                return false;
            }

            cursor = region_end < end ? region_end : end;
        }
        return true;
    }
} // namespace DetourModKit
