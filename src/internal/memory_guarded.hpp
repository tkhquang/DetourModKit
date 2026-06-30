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
         * @enum PatchStatus
         * @brief Outcome of patch_bytes (the protection-changing slow path of memory::write_bytes).
         */
        enum class PatchStatus
        {
            /// The bytes were written and the original protection restored.
            Ok,
            /// The page could not be made writable; nothing was written.
            ProtectionChangeFailed,
            /// The bytes were written but the original protection could not be restored.
            ProtectionRestoreFailed
        };

        /**
         * @brief Changes @p address's page(s) to writable, copies @p bytes, flushes the instruction cache, and restores
         *        the original protection.
         * @param address Destination address (caller has validated it is non-null and the size is in bounds).
         * @param source Source buffer.
         * @param bytes Byte count (caller has validated it is non-zero and within memory::MAX_WRITE_SIZE).
         * @param os_error Receives the OS error code from the failing VirtualProtect when the result is not Ok.
         * @return PatchStatus describing how far the protect / write / restore sequence got.
         * @details The slow path for read-only or executable targets (code patches). It is reached only after the
         *          no-reprotect guarded_write_bytes faulted, so the cache invalidation that must follow a protection
         *          change is the caller's responsibility (it owns the public memory::invalidate_range surface).
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
