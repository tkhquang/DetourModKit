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
         * @brief Guarded typed read for engine code: a representation-safe @p T at @p address, or nullopt on fault.
         * @tparam T A trivially copyable type for which every bit pattern is a valid object representation
         *           (@ref is_representation_safe_v). Read through untyped storage + bit_cast, so it need not be default
         *           constructible, but a representation-sensitive type such as bool is excluded: forming it from an
         *           arbitrary foreign byte would be undefined behaviour before the optional could report failure. Decode
         *           such a type from raw bytes instead (memory::read_bool for bool).
         * @details The engine-side counterpart of public memory::read<T>, returning std::optional instead of Result so
         *          the scan / RTTI inner loops keep the lightweight optional checks they already used. Forwards to
         *          guarded_read_bytes, so the __try frame stays in the engine TU.
         */
        template <class T>
            requires(std::is_trivially_copyable_v<T> && is_representation_safe_v<T>)
        [[nodiscard]] std::optional<T> guarded_read(std::uintptr_t address) noexcept
        {
            std::array<std::byte, sizeof(T)> storage{};
            if (!guarded_read_bytes(address, storage.data(), sizeof(T)))
            {
                return std::nullopt;
            }
            return std::bit_cast<T>(storage);
        }

        /** @brief Outcome of a guarded byte write that never changes protection. */
        enum class GuardedWriteStatus
        {
            Ok,
            NotWritten,
            MayBePartial
        };

        /**
         * @brief Guarded copy of @p bytes bytes from @p source into @p address, changing no page protection.
         * @param address Destination address. Below memory::USERSPACE_PTR_MIN, or a wrapping end, is rejected.
         * @param source Source buffer; null is rejected.
         * @param bytes Byte count; zero is a successful no-op.
         * @return Whether all bytes landed, the first byte faulted, or a later byte faulted after progress.
         * @details The forward-copy primitive exposes whether a fault occurred at byte zero or after progress, making
         *          `NotWritten` truthful without a racy permission query. This is memory::write_bytes' no-protect path.
         */
        [[nodiscard]] GuardedWriteStatus guarded_write_bytes(std::uintptr_t address, const void *source,
                                                             std::size_t bytes) noexcept;

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
            // Whether the segment was executable when this transaction began.
            bool originally_executable = false;
            // Identifies this transaction in the page ledger.
            std::uint64_t transaction_id = 0;
        };

        /** @brief Outcome of a multi-region protection change. */
        enum class ProtectionChangeStatus
        {
            Ok,
            ChangeFailed,
            RestoreFailed
        };

        /** @brief Result of changing a span's protection. */
        struct ProtectionChangeOutcome
        {
            std::size_t segment_count = 0;
            ProtectionChangeStatus status = ProtectionChangeStatus::ChangeFailed;
            std::uint32_t os_error = 0;
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
         * @brief Changes every VirtualQuery region overlapping the requested span and records it for restoration.
         * @param address First byte of the validated span.
         * @param bytes Validated non-zero span length.
         * @param new_protection Fixed Win32 PAGE_* value. Ignored when writable protection is derived.
         * @param out Caller-owned buffer receiving one @ref ProtectionSegment per region changed.
         * @param out_cap Capacity of @p out in elements.
         * @param derive_writable_preserving_execute When true, derive writable protection per region while
         *        preserving execute; otherwise use @p new_protection.
         * @return The captured segment count and whether the change, or its rollback, failed.
         * @details A process-wide ledger serializes protection transactions. Each page records its original
         *          protection and live holders in acquisition order. Removing an inner guard restores the newest
         *          surviving holder; removing the last restores the original. The span is walked by VirtualQuery
         *          region so protection seams restore exactly. Query, protection, capacity, and allocation failures
         *          fail closed. A rollback failure is reported separately because a temporary protection may remain.
         */
        [[nodiscard]] ProtectionChangeOutcome
        protect_across_regions(std::uintptr_t address, std::size_t bytes, std::uint32_t new_protection,
                               ProtectionSegment *out, std::size_t out_cap,
                               bool derive_writable_preserving_execute = false) noexcept;

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
         * @brief Drops @p segments from the protection ledger WITHOUT restoring their protection.
         * @param segments The segments to stop tracking (as filled by @ref protect_across_regions).
         * @param count Number of valid entries in @p segments.
         * @details The counterpart to @ref restore_across_regions for a guard that is intentionally abandoned
         *          (ProtectGuard::release keeps the changed protection permanently): the page stays at its changed
         *          protection, but its ledger depth must be released so the ledger does not carry a phantom transaction
         *          that would block a later overlapping guard from ever restoring, or make a reused page address resolve
         *          to a stale original. A page whose depth reaches zero is simply forgotten; the changed protection it
         *          is left at becomes the baseline a future guard captures.
         */
        void abandon_protection_tracking(const ProtectionSegment *segments, std::size_t count) noexcept;

        /**
         * @enum PatchStatus
         * @brief Outcome of patch_bytes (the protection-changing slow path of memory::write_bytes).
         */
        enum class PatchStatus
        {
            /// The bytes were written, the instruction cache flushed for executable regions, and protection restored.
            Ok,
            /// The page could not be made writable; nothing was written.
            ProtectionChangeFailed,
            /// The first target byte faulted after protection changed, so nothing was written.
            WriteFaulted,
            /**
             * The page was made writable but the guarded copy faulted (a concurrent reprotect / decommit of the
             * target); the original protection has been restored and the instruction cache flushed, and the write is
             * reported as failed rather than terminating the host. A forward-copy prefix may already have been written.
             */
            WriteMayBePartial,
            /// Bytes written and protection restored, but an executable region's instruction-cache flush failed.
            InstructionFlushFailed,
            /// The bytes were written but the original protection could not be restored.
            ProtectionRestoreFailed
        };

        /**
         * @brief Makes a span writable, performs a guarded copy and required cache flushes, then restores protection.
         * @param address Validated destination address.
         * @param source Source buffer.
         * @param bytes Validated non-zero byte count.
         * @param os_error Receives a failing VirtualProtect error for change or restoration failures.
         * @param flush_all_regions Flush every touched region when true; otherwise flush executable regions.
         * @return The outcome of the protect, copy, flush, and restore transaction.
         * @details Writable protection is derived per region, preserving execute without granting it to data.
         *          With @p flush_all_regions false, read-only data writes issue no cache flush. The guarded copy
         *          contains a concurrent reprotect or unmap fault, after which flush and restoration are still tried.
         *          Restoration failure outranks partial copy, which outranks cache-flush failure. The caller owns
         *          protection-cache invalidation.
         */
        [[nodiscard]] PatchStatus patch_bytes(std::uintptr_t address, const void *source, std::size_t bytes,
                                              std::uint32_t &os_error, bool flush_all_regions = false) noexcept;

        /**
         * @brief Flushes the instruction cache over [@p address, @p address + @p bytes), returning whether it
         *        succeeded.
         * @param address First byte to flush.
         * @param bytes Byte count.
         * @return true on success; false if FlushInstructionCache failed (or a test seam forced a failure).
         * @details The explicit code-patch fast path (memory::patch_code) calls this after a no-reprotect guarded write
         *          to an already-writable executable page, so an already-writable code patch still flushes -- the flush
         *          is what makes the newly written bytes visible to the instruction stream. A plain data write never
         *          calls it, keeping ordinary writes flush-free.
         */
        [[nodiscard]] bool flush_instruction_cache(std::uintptr_t address, std::size_t bytes) noexcept;

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
         * @details Every offset except the last is added and dereferenced to obtain the next link.
         *          The last is added but not dereferenced. Each intermediate link is screened against its hop's floor
         *          and the user-mode ceiling. A torn or sentinel pointer stops the walk before the next dereference.
         */
        [[nodiscard]] ChainWalkOutcome guarded_resolve_chain(Address base, const memory::ChainStep *steps,
                                                             std::size_t count, Address *trace,
                                                             std::size_t trace_cap) noexcept;

#if defined(DMK_ENABLE_TEST_SEAMS)
        /**
         * @brief Test seam: forces the next executable-region instruction-cache flush to report failure.
         * @details Set on the calling thread only, null/no-op by default, and compiled out of shipping archives. It
         *          makes otherwise unavailable FlushInstructionCache failure paths deterministic.
         */
        void set_flush_failure_seam(bool fail) noexcept;

        /**
         * @brief Test seam: makes @ref guarded_write_bytes copy one byte at a time and record the prefix it wrote.
         * @details Enabling it (thread-local, compiled out of shipping) turns the guarded copy into a forward
         *          byte-at-a-time loop so a write straddling a writable page into an unmapped one stops at a
         *          deterministic prefix; portable memcpy ordering is otherwise unspecified. @ref
         *          last_forward_copy_prefix returns the
         *          number of bytes the most recent guarded write committed before a fault (or the full length on
         *          success).
         */
        void set_forward_copy_seam(bool enable) noexcept;

        /// Test seam: bytes the most recent @ref guarded_write_bytes committed before a fault (forward-copy seam).
        [[nodiscard]] std::size_t last_forward_copy_prefix() noexcept;

        /** @brief Fails selected subsequent VirtualProtect calls by zero-based call-index bits. */
        void set_virtual_protect_failure_mask(std::uint64_t call_mask) noexcept;

        /// Resets the current thread's best-effort restoration diagnostic count.
        void reset_restore_diagnostic_count() noexcept;

        /// Returns the current thread's best-effort restoration diagnostic count.
        [[nodiscard]] std::size_t restore_diagnostic_count() noexcept;
#endif

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
         *          is unloaded. It waits for every guarded access already committed to the handler path to finish before
         *          unregistering, so a fault can never arrive after the handler is gone. Idempotent and re-installable: a
         *          later guarded access re-installs a fresh handler. A no-op on MSVC.
         */
        void release_guarded_engine() noexcept;
#endif
    } // namespace detail
} // namespace DetourModKit

#endif // DETOURMODKIT_INTERNAL_MEMORY_GUARDED_HPP
