#ifndef DETOURMODKIT_INTERNAL_MEMORY_GUARDED_HPP
#define DETOURMODKIT_INTERNAL_MEMORY_GUARDED_HPP

/**
 * @file memory_guarded.hpp
 * @brief Private engine interface for the guarded byte primitives that back the public memory::read / write / walk.
 *
 * The Structured Exception Handling (MSVC __try / MinGW vectored handler) and the VirtualProtect protection dance live
 * entirely in memory_guarded.cpp; the public memory_*.cpp translation units call only the small, value-free seam
 * declared here. Keeping the seam in src/internal/ -- never installed -- is how "SEH confined to one engine TU" is
 * satisfied while the public header stays Win32-free. The chain resolver takes the public memory::ChainStep by pointer
 * so the per-hop offset and plausibility floor reach the engine without a parallel-array copy.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @struct ModuleSpan
         * @brief The engine's raw half-open module range [base, end), in plain integers for hot arithmetic.
         * @details The scan engine, the RTTI walk, and the hooked-prologue recovery all work in raw addresses inside
         *          their inner loops, so they carry a module's extent as two uintptr_t rather than the public Region.
         *          A Region (the public scope vocabulary) converts to a ModuleSpan at each public boundary via
         *          module_span(); an empty Region yields an invalid span that contains() rejects.
         */
        struct ModuleSpan
        {
            std::uintptr_t base = 0;
            std::uintptr_t end = 0;

            /// True iff this span is populated (base != 0 && end > base).
            [[nodiscard]] constexpr bool valid() const noexcept { return base != 0 && end > base; }

            /// True iff the span is valid and @p address lies in [base, end).
            [[nodiscard]] constexpr bool contains(std::uintptr_t address) const noexcept
            {
                return valid() && address >= base && address < end;
            }
        };

        /// Converts a public Region scope into the engine's raw ModuleSpan; an empty Region yields an invalid span.
        [[nodiscard]] inline ModuleSpan module_span(Region scope) noexcept
        {
            return ModuleSpan{scope.base.raw(), scope.end().raw()};
        }

        /// Raw-integer form of memory::is_plausible_ptr for engine code that works in uintptr_t inside its hot loops.
        [[nodiscard]] inline constexpr bool is_plausible_ptr(std::uintptr_t address) noexcept
        {
            return memory::is_plausible_ptr(Address{address});
        }

        /**
         * @brief Resolves a loaded module's base address to the Region spanning its full mapped image.
         * @param module_base The module's base address (its HMODULE value); null yields an empty Region.
         * @return The module image span, or an empty Region when @p module_base is null or its PE headers do not
         *         validate.
         * @details The single canonical "module base -> Region" resolver, shared by region.cpp's Region factories
         *          (host/module_named/own) and memory::module_of so the PE-header walk -- DOS magic, a bounded e_lfanew,
         *          the NT signature, and OptionalHeader.SizeOfImage -- lives in one place rather than a raw-deref copy in
         *          each. The headers are read through the guarded engine, so a partially-mapped or corrupt image fails
         *          closed to an empty Region instead of faulting the host.
         */
        [[nodiscard]] Region module_image_region(Address module_base) noexcept;

        /**
         * @brief module_image_region cached per module handle for the process lifetime.
         * @param module_base The module's base address (its HMODULE value); null yields an empty Region.
         * @return The module image span, or an empty Region when @p module_base is null or its PE headers do not
         *         validate. Only valid (non-empty) results are cached.
         * @details The caching front end to @ref module_image_region, backed by a process-lifetime handle-keyed cache
         *          (a shared-lock hit on the fast path, an exclusive insert on the first resolve). memory::module_of and
         *          region.cpp's Region factories (host / own / module_named) both route through this so a repeated
         *          module-range query degenerates to a loader handle lookup plus a hash hit, instead of re-walking the
         *          PE headers (DOS magic, e_lfanew, NT signature, SizeOfImage) through the guarded engine every call.
         *          Entries are never invalidated on module unload, so a handle reused after unload can return a stale
         *          span -- an intentional, fault-contained tradeoff for the transient non-owning Region contract; the
         *          rationale (and when to resolve fresh instead) is documented on ModuleRangeCache in memory_module.cpp.
         */
        [[nodiscard]] Region cached_module_image_region(Address module_base) noexcept;

        /**
         * @brief Guarded copy of @p bytes bytes from @p address into @p out.
         * @param address Source address. Below memory::USERSPACE_PTR_MIN, or an end that wraps the address space, is
         *                rejected without a read.
         * @param out Destination buffer; null is rejected.
         * @param bytes Byte count; zero is a successful no-op.
         * @return true on full success; false on any fault or rejected argument (then @p out is unspecified).
         */
        [[nodiscard]] bool guarded_read_bytes(std::uintptr_t address, void *out, std::size_t bytes) noexcept;

        /**
         * @brief Guarded typed read for engine code: a trivially copyable @p T at @p address, or nullopt on fault.
         * @tparam T A trivially copyable type (read through untyped storage + bit_cast, so it need not be default
         *           constructible).
         * @details The engine-side counterpart of public memory::read<T>, returning std::optional instead of Result so
         *          the scan / RTTI inner loops keep the lightweight optional checks they already used. Forwards to
         *          guarded_read_bytes, so the __try frame stays in the engine TU.
         */
        template <class T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] std::optional<T> guarded_read(std::uintptr_t address) noexcept
        {
            std::array<std::byte, sizeof(T)> storage{};
            if (!guarded_read_bytes(address, storage.data(), sizeof(T)))
            {
                return std::nullopt;
            }
            return std::bit_cast<T>(storage);
        }

        /**
         * @brief Guarded copy of @p bytes bytes from @p source into @p address, changing no page protection.
         * @param address Destination address. Below memory::USERSPACE_PTR_MIN, or a wrapping end, is rejected.
         * @param source Source buffer; null is rejected.
         * @param bytes Byte count; zero is a successful no-op.
         * @return true on full success; false on any fault (the destination was not writable) or rejected argument.
         * @details This is the fast path of memory::write_bytes: it never calls VirtualProtect, so a write to a
         *          read-only or executable page fails (the caller then takes patch_bytes). A write to an
         *          already-writable page succeeds with no syscall.
         */
        [[nodiscard]] bool guarded_write_bytes(std::uintptr_t address, const void *source, std::size_t bytes) noexcept;

        /**
         * @struct ProtectionSegment
         * @brief One VirtualQuery region within a protection-changed span, plus the protection to restore it to.
         * @details A write or a ProtectGuard may cover a span that crosses a `.rdata`/`.text` (or any) protection seam,
         *          so it is not one uniform-protection block. VirtualProtect over the whole span reports only the
         *          first page's prior protection, so restoring the whole span to that single value flattens an
         *          executable page adjacent to a read-only seam down to PAGE_READONLY (its next execution then AVs
         *          under DEP). The span is therefore changed and restored one VirtualQuery region at a time; each
         *          region's own prior protection is captured here so the restore is exact per region.
         */
        struct ProtectionSegment
        {
            // First byte of the touched sub-span within this region.
            std::uintptr_t base = 0;
            // Length of the touched sub-span (VirtualProtect operates on whole pages).
            std::size_t size = 0;
            // The region's protection before the change, restored on unwind (a Win32 DWORD stored width-safely).
            std::uint32_t old_protection = 0;
        };

        /**
         * @brief Upper bound on distinct protection regions a single span may cross before @ref protect_across_regions
         *        fails closed.
         * @details A real write or guard site spans one to a few regions; a span crossing this many alternating
         *          protection blocks is not a legitimate patch, so the cap is a defensive ceiling, not a functional
         *          limit.
         */
        inline constexpr std::size_t MAX_PROTECTION_SEGMENTS = 64;

        /**
         * @brief Changes every VirtualQuery region overlapping [address, address + bytes) to @p new_protection,
         *        capturing each region's prior protection so it can be restored exactly.
         * @param address First byte of the span (caller has validated non-null / in-bounds).
         * @param bytes Span length in bytes (caller has validated non-zero and non-wrapping).
         * @param new_protection The Win32 PAGE_* value to apply to every region in the span.
         * @param out Caller-owned buffer receiving one @ref ProtectionSegment per region changed.
         * @param out_cap Capacity of @p out in elements.
         * @param os_error Receives the OS error from the failing VirtualQuery / VirtualProtect on failure.
         * @return The number of regions changed (written to @p out) on full success; 0 on failure, in which case every
         *         region already changed has been rolled back to its captured protection before returning.
         * @details Walks the span region by region (VirtualQuery to find each region's extent, VirtualProtect over the
         *          sub-span within it) rather than one whole-span VirtualProtect, so a span crossing a protection seam
         *          captures and later restores each region's own protection instead of the first region's flattened
         *          over all of them. Fails closed (returns 0, rolling back) if a region cannot be queried or protected,
         *          or if the span crosses more than @p out_cap regions.
         */
        [[nodiscard]] std::size_t protect_across_regions(std::uintptr_t address, std::size_t bytes,
                                                         std::uint32_t new_protection, ProtectionSegment *out,
                                                         std::size_t out_cap, std::uint32_t &os_error) noexcept;

        /**
         * @brief Restores every segment captured by @ref protect_across_regions to its recorded prior protection.
         * @param segments The segments to restore (as filled by @ref protect_across_regions).
         * @param count Number of valid entries in @p segments.
         * @param os_error Receives the OS error from the first failing VirtualProtect (captured before any later call
         *        or FlushInstructionCache can overwrite GetLastError).
         * @return true if every segment restored; false if any VirtualProtect failed (best-effort: it still attempts
         *         the remaining segments so a single failure does not strand the rest in the changed protection).
         */
        [[nodiscard]] bool restore_across_regions(const ProtectionSegment *segments, std::size_t count,
                                                  std::uint32_t &os_error) noexcept;

        /**
         * @enum PatchStatus
         * @brief Outcome of patch_bytes (the protection-changing slow path of memory::write_bytes).
         */
        enum class PatchStatus
        {
            /// The bytes were written and the original protection restored.
            Ok,
            /// The page could not be made writable; nothing was written.
            ProtectionChangeFailed,
            /**
             * The page was made writable but the guarded copy faulted (a concurrent reprotect / decommit of the
             * target); the original protection has been restored and the instruction cache flushed, and the write is
             * reported as failed rather than terminating the host. The target may have been partially written.
             */
            WriteFaulted,
            /// The bytes were written but the original protection could not be restored.
            ProtectionRestoreFailed
        };

        /**
         * @brief Changes @p address's page(s) to writable, copies @p bytes through the fault guard, flushes the
         *        instruction cache, and restores the original protection.
         * @param address Destination address (caller has validated it is non-null and the size is in bounds).
         * @param source Source buffer.
         * @param bytes Byte count (caller has validated it is non-zero and within memory::MAX_WRITE_SIZE).
         * @param os_error Receives the OS error code from the failing VirtualProtect when the result is
         *        ProtectionChangeFailed or ProtectionRestoreFailed.
         * @return PatchStatus describing how far the protect / write / restore sequence got.
         * @details The slow path for read-only or executable targets (code patches). It is reached only after the
         *          no-reprotect guarded_write_bytes faulted, so the cache invalidation that must follow a protection
         *          change is the caller's responsibility (it owns the public memory::invalidate_range surface). The copy
         *          runs through guarded_write_bytes rather than a bare memcpy so that a fault mid-copy (the page
         *          reprotected or unmapped out from under this noexcept host path) is contained: the protection restore
         *          and the flush still run on that exit, `ProtectionRestoreFailed` takes priority if the restore fails,
         *          and otherwise the caller learns the write did not complete (`WriteFaulted`) instead of the process
         *          terminating.
         */
        [[nodiscard]] PatchStatus patch_bytes(std::uintptr_t address, const void *source, std::size_t bytes,
                                              std::uint32_t &os_error) noexcept;

        /**
         * @struct ChainWalkOutcome
         * @brief Result of guarded_resolve_chain: the resolved leaf, or the hop index at which the walk failed.
         */
        struct ChainWalkOutcome
        {
            /// The resolved leaf address; meaningful only when @ref ok is true.
            Address address{};
            /// Index of the hop that faulted or yielded an implausible link; meaningful only when @ref ok is false.
            std::size_t fail_index{0};
            /// True when the whole chain resolved.
            bool ok{false};
        };

        /**
         * @brief Resolves a Cheat-Engine-style pointer chain under a single fault guard, capturing intermediates.
         * @param base Root address of the chain.
         * @param steps One memory::ChainStep per hop (offset + per-hop plausibility floor).
         * @param count Number of hops.
         * @param trace Optional out-buffer; when non-null, trace[i] receives the value resolved at hop i for the first
         *              @p trace_cap hops, populated for the successfully-walked prefix even on failure.
         * @param trace_cap Capacity of @p trace in elements (0 when @p trace is null).
         * @return A ChainWalkOutcome: ok + leaf on success, or !ok + the failing hop index.
         * @details Every offset except the last is added and dereferenced to obtain the next link; the last is added
         * but
         *          not dereferenced. Each intermediate link is screened against its hop's floor and the user-mode
         *          ceiling, so a torn or sentinel pointer stops the walk at that hop before the next dereference faults.
         */
        [[nodiscard]] ChainWalkOutcome guarded_resolve_chain(Address base, const memory::ChainStep *steps,
                                                             std::size_t count, Address *trace,
                                                             std::size_t trace_cap) noexcept;

#if !defined(_MSC_VER) && defined(_WIN64)
        /**
         * @brief Eagerly installs the MinGW process-wide vectored fault handler the guarded reads rely on.
         * @details Lazy install also happens on the first guarded access, so this is purely an optimization: the cache
         *          setup path calls it so the handler is present before a hook callback can be the first guarded read,
         *          sparing that first read the VirtualQuery fallback. A no-op on MSVC (frame-based __try needs no
         *          handler), hence the MinGW-x64 guard. Best-effort: a failed install only costs guarded reads their
         *          fallback.
         */
        void ensure_guarded_engine_installed() noexcept;

        /**
         * @brief Drains in-flight guarded accesses, then removes the MinGW vectored fault handler.
         * @details Called on memory-subsystem teardown so the handler cannot dangle into freed code if the DMK module
         * is
         *          unloaded. It waits for every guarded access already committed to the handler path to finish before
         *          unregistering, so a fault can never arrive after the handler is gone. Idempotent and re-installable: a
         *          later guarded access re-installs a fresh handler. A no-op on MSVC.
         */
        void release_guarded_engine() noexcept;
#endif
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_MEMORY_GUARDED_HPP
