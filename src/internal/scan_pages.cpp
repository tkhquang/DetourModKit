/**
 * @file internal/scan_pages.cpp
 * @brief Page-gated AOB scanning: the VirtualQuery region walk, the per-region TOCTOU fault guard, the committed-window
 *        collector, and the single-address executable-page predicate.
 * @details Wraps the raw matcher in the OS page map so a scan over arbitrary process memory reads only committed pages
 *          of the requested protection class. The incomplete-scan state rides on a MatchResult return value (and an
 *          internal out-parameter) rather than a thread-local side channel, so concurrent scans cannot clobber each
 *          other's fault state. The Windows page-protection masks stay private to this TU; callers reach them only
 *          through the named module / whole-process scans and the Pages mapping.
 */

#include "internal/scan_pages.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include "internal/memory_fault.hpp"

#include <windows.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        // Scan one protection-gated region for the next needed match, decrementing matches_remaining for each non-self
        // match. Returns the resolved address (match + pattern.offset) when the Nth match lands in this region, or
        // nullptr when the region is exhausted first. This is the body the TOCTOU fault guard wraps (see
        // scan_region_guarded): it performs the unguarded find_pattern_raw reads (memchr prefilter + SIMD verify)
        // across [region_start, +scan_size).
        const std::byte *scan_region_for_match(const std::byte *region_start, std::size_t scan_size,
                                               const detail::EnginePattern &pattern, std::uintptr_t needle_lo,
                                               std::uintptr_t needle_hi, std::size_t &matches_remaining) noexcept
        {
            const std::byte *match = detail::find_pattern_raw(region_start, scan_size, pattern);
            while (match != nullptr)
            {
                const auto match_addr = reinterpret_cast<std::uintptr_t>(match);
                const bool self_match = match_addr < needle_hi && (match_addr + pattern.size()) > needle_lo;
                if (!self_match)
                {
                    --matches_remaining;
                    if (matches_remaining == 0)
                        return match + pattern.offset;
                }

                // Continue scanning past the current match.
                const std::size_t consumed = static_cast<std::size_t>(match - region_start) + 1;
                if (consumed >= scan_size)
                    break;
                match = detail::find_pattern_raw(match + 1, scan_size - consumed, pattern);
            }
            return nullptr;
        }

        // Region-granular TOCTOU fault guard around scan_region_for_match. The caller's per-region VirtualQuery only
        // proves the region was committed and readable at gate time; a concurrent decommit / reprotect before these
        // unguarded reads complete would otherwise fault the host. On MSVC the body runs inside a __try / __except that
        // swallows exactly the foreign-read faults (detail::is_guarded_read_fault) and reports the region as
        // faulted, so the sweep skips it and continues -- the same skip-the-region contract guarded_read_bytes follows.
        // On MinGW x64 the same scan runs through the process-wide vectored read guard
        // (detail::run_guarded_region) that the guarded_read paths use, so a fault inside the scanned span is
        // swallowed and the region is skipped + counted there too. On 32-bit MinGW that x64-only vectored guard is
        // unavailable, so the body runs directly and the per-region VirtualQuery gate is the only guard. *out_faulted
        // is set true only when a fault was swallowed.
        const std::byte *scan_region_guarded(const std::byte *region_start, std::size_t scan_size,
                                             const detail::EnginePattern &pattern, std::uintptr_t needle_lo,
                                             std::uintptr_t needle_hi, std::size_t &matches_remaining,
                                             bool &out_faulted) noexcept
        {
            // The 64-bit-only contract, asserted locally so the unguarded 32-bit MinGW arm of this function (the bare
            // #else below, which runs scan_region_for_match with no vectored fault guard) is provably unreachable in
            // any build that compiles: a 32-bit build fails here at compile time rather than silently shipping a sweep
            // whose only TOCTOU protection is the per-region VirtualQuery gate.
            static_assert(sizeof(void *) == 8, "scan_region_guarded requires a 64-bit target: the MinGW fault guard "
                                               "(run_guarded_region) is x64-only and the 32-bit arm is unguarded.");
            out_faulted = false;
#ifdef _MSC_VER
            const std::size_t original_matches_remaining = matches_remaining;
            __try
            {
                return scan_region_for_match(region_start, scan_size, pattern, needle_lo, needle_hi, matches_remaining);
            }
            __except (detail::is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER
                                                                        : EXCEPTION_CONTINUE_SEARCH)
            {
                // Treat a faulted region as skipped, not partially scanned. Matches observed before the fault cannot be
                // trusted for Nth-occurrence accounting because unreadable tail bytes may hide additional matches.
                matches_remaining = original_matches_remaining;
                out_faulted = true;
                return nullptr;
            }
#elif defined(_WIN64)
            // MinGW x64: route the unguarded find_pattern_raw sweep through the same vectored fault guard the foreign-
            // read primitives use. The guard is armed over exactly the bytes the per-region gate proved readable; a
            // concurrent decommit / reprotect that faults the sweep is swallowed and the region is skipped + counted,
            // closing the TOCTOU window the bare gate cannot.
            struct ScanContext
            {
                const std::byte *region_start;
                std::size_t scan_size;
                const detail::EnginePattern *pattern;
                std::uintptr_t needle_lo;
                std::uintptr_t needle_hi;
                std::size_t *matches_remaining;
                const std::byte *result;
            } scan_ctx{region_start, scan_size, &pattern, needle_lo, needle_hi, &matches_remaining, nullptr};

            const std::size_t original_matches_remaining = matches_remaining;
            const auto run_scan = [](void *opaque) noexcept -> void
            {
                auto *context = static_cast<ScanContext *>(opaque);
                context->result =
                    scan_region_for_match(context->region_start, context->scan_size, *context->pattern,
                                          context->needle_lo, context->needle_hi, *context->matches_remaining);
            };

            const auto span_lo = reinterpret_cast<std::uintptr_t>(region_start);
            if (detail::run_guarded_region(span_lo, span_lo + scan_size, run_scan, &scan_ctx))
            {
                return scan_ctx.result;
            }
            // A faulted region is skipped, not partially scanned: restore the count so unreadable tail bytes that may
            // hide additional matches cannot corrupt Nth-occurrence accounting -- the same contract as the MSVC path.
            matches_remaining = original_matches_remaining;
            out_faulted = true;
            return nullptr;
#else
            return scan_region_for_match(region_start, scan_size, pattern, needle_lo, needle_hi, matches_remaining);
#endif
        }

        // Region-walking AOB scan shared by the whole-process scans and the module-scoped entry points. Walks the
        // committed regions of [window_lo, window_hi) via VirtualQuery and runs the per-region scan
        // (scan_region_for_match, behind the fault guard) against every region whose base protection is present in
        // accept_mask, returning the Nth match (1-based, adjusted by pattern.offset) or nullptr. The whole-process
        // scanners pass [0, UINTPTR_MAX); the module-scoped scan passes the image's [base, end) so only one contiguous
        // image is searched. *out_incomplete is set true when any region faulted mid-scan and was skipped, so the
        // caller can tell that an occurrence count is only a lower bound.
        //
        // Guard, no-access, and uncommitted regions are always skipped: PAGE_GUARD raises STATUS_GUARD_PAGE_VIOLATION
        // on the first touch and PAGE_NOACCESS faults even for reads, so neither is safe to dereference. The Windows
        // base protections (PAGE_READONLY, PAGE_READWRITE, ... , PAGE_EXECUTE_WRITECOPY) are mutually exclusive single
        // bits, so a bitwise-AND against a mask of the acceptable bases is a sound membership test. PAGE_GUARD is a
        // modifier bit OR-ed onto a base value (a guarded read-only page reads as PAGE_READONLY | PAGE_GUARD), so it
        // must be excluded separately or it would satisfy the mask and be scanned.
        //
        // Each region is scanned through the raw helper so the final `+ pattern.offset` applies exactly once. To find a
        // signature that straddles a protection split -- two adjacent accepted regions VirtualQuery reports separately
        // because their base protections differ (a sibling VirtualProtect carving part of .text into
        // PAGE_EXECUTE_READWRITE is the canonical case; VirtualQuery never coalesces regions with differing
        // attributes) -- each accepted region's scan is extended back by up to pattern_size - 1 bytes into the
        // contiguous run of already-accepted regions it abuts. The overlap is capped at pattern_size - 1 so a match
        // lying wholly inside the previous region (already counted there) can never be re-counted here, and bounded by
        // the run start so it never reads past the bytes the per-region gate proved readable.
        const std::byte *scan_regions_filtered(const detail::EnginePattern &pattern, std::size_t occurrence,
                                               DWORD accept_mask, std::uintptr_t window_lo, std::uintptr_t window_hi,
                                               bool &out_incomplete) noexcept
        {
            // The compiled pattern's own bytes buffer lives in readable heap memory, so a whole-process readable sweep
            // would match the needle against itself and could return the caller's pattern storage instead of the
            // intended target. Exclude any match that overlaps that buffer. The executable sweep never reaches
            // pattern.bytes (the heap is not executable), so this is a no-op there and keeps both scanners consistent:
            // a scan never matches the needle's own storage. The needle is the caller's allocation, so no real target
            // can share its range.
            const auto needle_lo = reinterpret_cast<std::uintptr_t>(pattern.bytes.data());
            const auto needle_hi = needle_lo + pattern.size();

            std::size_t matches_remaining = occurrence;
            std::size_t faulted_regions = 0;
            std::size_t total_faulted = 0;
            MEMORY_BASIC_INFORMATION mbi{};
            std::uintptr_t addr = window_lo;

            // Contiguous-accepted-run tracking for the cross-boundary overlap (see the function comment).
            // prev_accept_hi is the end of the previous accepted region; run_lo is the start of the run of contiguous
            // accepted regions the current region belongs to. A gap (a skipped, guarded, or non-readable region) breaks
            // the run because the bytes across it are not proven readable.
            bool prev_accepted = false;
            std::uintptr_t prev_accept_hi = 0;
            std::uintptr_t run_lo = 0;
            auto report_faulted_regions = [&]() noexcept
            {
                if (faulted_regions == 0)
                    return;

                // Surface the incomplete-scan state so a uniqueness / occurrence count run over a window that skipped a
                // faulted region can fail closed: a hidden match could live in the skipped bytes, so a count taken here
                // is a lower bound, not a proof. Accumulate across every region walk this call performs.
                total_faulted += faulted_regions;

                // Best-effort diagnosis only; the sweep already skipped each faulted region and continued.
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

                // Surface the same skipped-region count to subscribers as a typed event. The dispatcher is lazy and can
                // allocate on first use, so diagnostics must never change the scan result.
                try
                {
                    Diagnostics::scanner_faults().emit_safe(Diagnostics::ScannerFaultEvent{
                        .faulted_regions = faulted_regions, .window_low = window_lo, .window_high = window_hi});
                }
                catch (...)
                {
                }
                faulted_regions = 0;
            };

            while (addr < window_hi && VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            {
                const bool protection_unsafe = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
                const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t region_end = region_base + mbi.RegionSize;

                // Clamp the region to the requested window so a region that straddles window_lo / window_hi is
                // inspected only where it intersects. For a whole-process sweep the window is [0, UINTPTR_MAX), so the
                // clamp is a no-op and the scanned span equals the region. For a module-scoped sweep this is what keeps
                // the scan inside [base, end) even when a VirtualQuery region (e.g. a section straddling the image
                // boundary) extends past it.
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

                    // Extend the scan back by up to pattern_size - 1 bytes into the contiguous accepted run so a match
                    // that begins in the previous region's tail and ends in this one is found. Bounded by run_lo so the
                    // read stays inside already-gated bytes; capped at pattern_size - 1 so an interior match is not
                    // re-counted.
                    std::uintptr_t effective_scan_lo = scan_lo;
                    if (pattern.size() > 1 && scan_lo > run_lo)
                    {
                        const std::uintptr_t max_overlap = static_cast<std::uintptr_t>(pattern.size() - 1);
                        const std::uintptr_t available = scan_lo - run_lo;
                        effective_scan_lo = scan_lo - ((max_overlap < available) ? max_overlap : available);
                    }

                    const std::size_t scan_size = static_cast<std::size_t>(scan_hi - effective_scan_lo);
                    if (scan_size >= pattern.size())
                    {
                        const auto *region_start = reinterpret_cast<const std::byte *>(effective_scan_lo);

                        // The protection gate above proved the region readable at gate time; scan_region_guarded
                        // backstops a concurrent decommit / reprotect that could fault the read after the gate (a
                        // TOCTOU the gate cannot close). A faulted region is skipped and counted, not fatal.
                        bool region_faulted = false;
                        const std::byte *result = scan_region_guarded(region_start, scan_size, pattern, needle_lo,
                                                                      needle_hi, matches_remaining, region_faulted);
                        if (result != nullptr)
                        {
                            report_faulted_regions();
                            out_incomplete = total_faulted > 0;
                            return result;
                        }
                        if (region_faulted)
                            ++faulted_regions;
                    }

                    prev_accepted = true;
                    prev_accept_hi = scan_hi;
                }
                else
                {
                    prev_accepted = false;
                }

                assert(region_end > addr && "VirtualQuery returned a non-advancing region");
                if (region_end <= addr)
                    break; // Overflow guard.
                addr = region_end;
            }

            report_faulted_regions();
            out_incomplete = total_faulted > 0;
            return nullptr;
        }

        // Base protections accepted by the executable-only sweeps: the three page variants that grant execute *and*
        // read. Bare PAGE_EXECUTE (execute without a read bit) is excluded because dereferencing it raises an access
        // violation; PAGE_GUARD / PAGE_NOACCESS are filtered separately inside scan_regions_filtered. This is the scope
        // for code-only scans: the whole-process executable sweep and the prologue-recovery fallback, whose rebuilt
        // near-JMP can only ever overwrite a code prologue.
        constexpr DWORD EXECUTABLE_PAGE_FLAGS = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        // Base protections accepted by the readable sweep and the data-capable module-scoped scan: the
        // executable-readable set plus the non-executable readable pages (.rdata / .data and read-only heaps). This
        // reaches C++ vtables, RTTI type descriptors, and other read-only metadata the executable-only sweep cannot
        // see.
        constexpr DWORD READABLE_PAGE_FLAGS = EXECUTABLE_PAGE_FLAGS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;
    } // anonymous namespace

    detail::MatchResult detail::scan_module_executable(const detail::EnginePattern &pattern, detail::ModuleSpan range,
                                                       std::size_t occurrence) noexcept
    {
        // EXECUTABLE_PAGE_FLAGS confines the match to code: the prologue-recovery fallback's rebuilt near-JMP can only
        // ever overwrite a code prologue, so a data-page hit would be a false positive.
        if (pattern.empty() || occurrence == 0 || !range.valid())
        {
            return MatchResult{nullptr, false};
        }
        bool incomplete = false;
        const std::byte *match =
            scan_regions_filtered(pattern, occurrence, EXECUTABLE_PAGE_FLAGS, range.base, range.end, incomplete);
        return MatchResult{match, incomplete};
    }

    detail::MatchResult detail::scan_module_readable(const detail::EnginePattern &pattern, detail::ModuleSpan range,
                                                     std::size_t occurrence) noexcept
    {
        // READABLE_PAGE_FLAGS lets one pass cover both .text and .rdata / .data candidates, which is why the in-module
        // scan needs no executable-vs-readable split.
        if (pattern.empty() || occurrence == 0 || !range.valid())
        {
            return MatchResult{nullptr, false};
        }
        bool incomplete = false;
        const std::byte *match =
            scan_regions_filtered(pattern, occurrence, READABLE_PAGE_FLAGS, range.base, range.end, incomplete);
        return MatchResult{match, incomplete};
    }

    detail::MatchResult detail::scan_executable_regions(const detail::EnginePattern &pattern,
                                                        std::size_t occurrence) noexcept
    {
        if (pattern.empty() || occurrence == 0)
        {
            return MatchResult{nullptr, false};
        }
        // EXECUTABLE_PAGE_FLAGS keeps the sweep to pages we can actually *read*; bare PAGE_EXECUTE grants execute
        // without read, so dereferencing such a page would raise an access violation. The window spans the entire user
        // address space, so the clamp in scan_regions_filtered is a no-op and the walk stops only when VirtualQuery
        // runs off the end of the address space.
        bool incomplete = false;
        const std::byte *match =
            scan_regions_filtered(pattern, occurrence, EXECUTABLE_PAGE_FLAGS, 0, UINTPTR_MAX, incomplete);
        return MatchResult{match, incomplete};
    }

    detail::MatchResult detail::scan_readable_regions(const detail::EnginePattern &pattern,
                                                      std::size_t occurrence) noexcept
    {
        if (pattern.empty() || occurrence == 0)
        {
            return MatchResult{nullptr, false};
        }
        // READABLE_PAGE_FLAGS is a superset of the executable-only mask: every committed region we can read, including
        // .rdata / .data and read-only heaps, plus the execute-readable variants. The window spans the whole address
        // space.
        bool incomplete = false;
        const std::byte *match =
            scan_regions_filtered(pattern, occurrence, READABLE_PAGE_FLAGS, 0, UINTPTR_MAX, incomplete);
        return MatchResult{match, incomplete};
    }

    detail::MatchResult detail::scan_module_pages(const detail::EnginePattern &pattern, detail::ModuleSpan range,
                                                  scan::Pages pages, std::size_t occurrence) noexcept
    {
        // Pages::Executable narrows to code pages; Pages::Readable is the data-capable superset (the default).
        return (pages == scan::Pages::Executable) ? scan_module_executable(pattern, range, occurrence)
                                                  : scan_module_readable(pattern, range, occurrence);
    }

    // Centralizes the executable-page protection gate for out-of-TU callers (the string-xref backend): one VirtualQuery
    // walk over [range.base, range.end) that returns each committed, execute-readable region clamped to the range,
    // using the identical mask scan_module_executable applies. The per-region gate (MEM_COMMIT, EXECUTABLE_PAGE_FLAGS,
    // not PAGE_GUARD / PAGE_NOACCESS) guarantees the window is readable at gate time; the caller still wraps its reads
    // of the window in a fault guard so a concurrent decommit / reprotect between gate and read cannot fault the host.
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

    // Single-address sibling of the executable-page gate scan_regions_filtered applies per region. One VirtualQuery,
    // matched against the identical mask (MEM_COMMIT, EXECUTABLE_PAGE_FLAGS, not PAGE_GUARD / PAGE_NOACCESS), so the
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
} // namespace DetourModKit
