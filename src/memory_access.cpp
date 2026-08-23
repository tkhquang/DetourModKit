/**
 * @file memory_access.cpp
 * @brief Public faces of the guarded access surface: read_into, write_bytes, and the pointer-chain walk.
 *
 * These translation units hold no Structured Exception Handling and touch no Win32 directly: they validate arguments in
 * the v4 value vocabulary (Address / Region / Result / Error), call the SEH-confined engine in memory_guarded.cpp, and
 * map the engine's plain bool / status results onto ErrorCode. The header-side read<T> / write<T> templates forward
 * into read_into / write_bytes defined here, so the only typed-read machinery in the installed header is a bit_cast.
 */

#include "DetourModKit/memory.hpp"

#include "internal/memory_guarded.hpp"

#include <array>
#include <cstddef>
#include <limits>
#include <span>

namespace DetourModKit
{
    namespace memory
    {
        namespace
        {
            /**
             * @brief Reports whether the half-open ranges [a, a+a_size) and [b, b+b_size) intersect.
             * @details Wrap-safe by construction. It subtracts the smaller base from the larger and compares against
             *          the lower range's size, so no sum can overflow. The engine separately rejects a range whose
             *          own end crosses the address-space boundary.
             */
            [[nodiscard]] constexpr bool
            ranges_overlap(std::uintptr_t a, std::size_t a_size, std::uintptr_t b, std::size_t b_size) noexcept
            {
                if (a_size == 0 || b_size == 0)
                {
                    return false;
                }
                return a <= b ? (b - a) < a_size : (a - b) < b_size;
            }

            constexpr std::uintptr_t ADDRESS_MAX = std::numeric_limits<std::uintptr_t>::max();
            static_assert(ranges_overlap(ADDRESS_MAX - 7, 8, ADDRESS_MAX - 3, 1));
            static_assert(ranges_overlap(ADDRESS_MAX, 1, ADDRESS_MAX, 1));
            static_assert(!ranges_overlap(ADDRESS_MAX - 7, 0, ADDRESS_MAX - 3, 1));

            /// Refuses a caller span that intersects the target range, in either direction (see T-OVERLAP).
            [[nodiscard]] bool
            span_overlaps_target(Address address, const void *span_data, std::size_t span_size) noexcept
            {
                return ranges_overlap(address.raw(), span_size, reinterpret_cast<std::uintptr_t>(span_data), span_size);
            }

            // Maps a protection-changing patch outcome onto the public Result, invalidating the cached protection for
            // the touched range on every exit (every slow-path exit changed protection, and a failed change still
            // rolled back regions it had already flipped, so a snapshot a concurrent reader cached from the transient
            // protection must not survive). Shared by write_bytes and patch_code.
            [[nodiscard]] Result<void> finish_patch(
                detail::PatchStatus status,
                std::uint32_t os_error,
                const char *where,
                Address address,
                std::size_t size,
                detail::GuardedWriteStatus fast_status
            ) noexcept
            {
                invalidate_range(Region{address, size});
                switch (status)
                {
                case detail::PatchStatus::Ok:
                    return {};
                case detail::PatchStatus::WriteMayBePartial:
                    return std::unexpected(Error{ErrorCode::WriteMayBePartial, where, address.raw(), 0});
                case detail::PatchStatus::WriteFaulted:
                    if (fast_status == detail::GuardedWriteStatus::MayBePartial)
                    {
                        return std::unexpected(Error{ErrorCode::WriteMayBePartial, where, address.raw(), 0});
                    }
                    return std::unexpected(Error{ErrorCode::WriteFaulted, where, address.raw(), 0});
                case detail::PatchStatus::InstructionFlushFailed:
                    return std::unexpected(Error{ErrorCode::InstructionFlushFailed, where, address.raw(), 0});
                case detail::PatchStatus::ProtectionRestoreFailed:
                    return std::unexpected(Error{ErrorCode::ProtectionRestoreFailed, where, address.raw(), os_error});
                case detail::PatchStatus::ProtectionChangeFailed:
                default:
                    // The escalation could not make the whole span writable (e.g. an unmapped tail). If the
                    // no-reprotect fast path already modified a writable-head prefix, the target is partially written;
                    // otherwise nothing was written and the protection change simply failed.
                    if (fast_status == detail::GuardedWriteStatus::MayBePartial)
                    {
                        return std::unexpected(Error{ErrorCode::WriteMayBePartial, where, address.raw(), 0});
                    }
                    return std::unexpected(Error{ErrorCode::ProtectionChangeFailed, where, address.raw(), os_error});
                }
            }
        } // namespace

        Result<void> read_into(Address address, std::span<std::byte> out) noexcept
        {
            if (out.empty())
            {
                return {};
            }
            if (span_overlaps_target(address, out.data(), out.size()))
            {
                return std::unexpected(Error{ErrorCode::OverlappingRanges, "memory::read_into", address.raw(), 0});
            }
            // Seed with the requested address so the argument-rejection paths (below USERSPACE_PTR_MIN, wrapping or
            // over-ceiling span, VirtualQuery fallback) still name an address: those refuse before any access, so there
            // is no faulting address to report and the guard leaves the slot untouched.
            volatile std::uintptr_t fault_address = address.raw();
            if (!detail::guarded_read_bytes(address.raw(), out.data(), out.size(), &fault_address))
            {
                return std::unexpected(Error{ErrorCode::ReadFaulted, "memory::read_into", fault_address, 0});
            }
            return {};
        }

        Result<bool> read_bool(Address address) noexcept
        {
            std::byte raw{};
            if (auto outcome = read_into(address, std::span<std::byte>{&raw, 1}); !outcome)
            {
                return std::unexpected(outcome.error());
            }
            // Validate the byte BEFORE forming the bool: only 0 and 1 are valid bool object representations, so an
            // arbitrary foreign byte can never be bit-cast into an invalid bool (undefined behaviour the raw read
            // excludes at compile time; this checked route reports it as InvalidRepresentation instead).
            switch (std::to_integer<unsigned char>(raw))
            {
            case 0:
                return false;
            case 1:
                return true;
            default:
                return std::unexpected(Error{ErrorCode::InvalidRepresentation, "memory::read_bool", address.raw(), 0});
            }
        }

        Result<void> write_bytes(Address address, std::span<const std::byte> source) noexcept
        {
            // Validation order: a null target outranks a null source, and a zero-length write is a success no-op that
            // never inspects the source pointer or the size cap.
            if (!address)
            {
                return std::unexpected(Error{ErrorCode::NullTargetAddress, "memory::write_bytes", address.raw(), 0});
            }
            if (source.data() == nullptr && !source.empty())
            {
                return std::unexpected(Error{ErrorCode::NullSourceBytes, "memory::write_bytes", address.raw(), 0});
            }
            if (source.empty())
            {
                return {};
            }
            if (source.size() > MAX_WRITE_SIZE)
            {
                return std::unexpected(Error{ErrorCode::SizeTooLarge, "memory::write_bytes", address.raw(), 0});
            }
            if (span_overlaps_target(address, source.data(), source.size()))
            {
                return std::unexpected(Error{ErrorCode::OverlappingRanges, "memory::write_bytes", address.raw(), 0});
            }

            // Fast path: a guarded write that changes no protection. It succeeds for an already-writable target (a
            // live game field, or any page held writable by a ProtectGuard) with no VirtualProtect and no flush, so a
            // per-frame writer stays off the syscall path.
            const detail::GuardedWriteStatus fast_status =
                detail::guarded_write_bytes(address.raw(), source.data(), source.size());
            if (fast_status == detail::GuardedWriteStatus::Ok)
            {
                return {};
            }

            if (fast_status == detail::GuardedWriteStatus::MayBePartial)
            {
                // The fallback flushes the executable regions it makes writable, but a setup failure leaves no segment
                // to flush, so an executable prefix this attempt may already have changed is covered here. A
                // non-executable target owes nothing and stays on the flush-free data route.
                detail::flush_if_executable(address.raw(), source.size());
            }

            // Slow path: the target was read-only or executable (or straddles into one), so the engine changes
            // protection (writable derived per region from its own execute semantics), writes, flushes executable
            // regions, and restores. If the span cannot be made fully writable and a prefix was already written,
            // finish_patch reports WriteMayBePartial rather than a clean ProtectionChangeFailed.
            std::uint32_t os_error = 0;
            const detail::PatchStatus status =
                detail::patch_bytes(address.raw(), source.data(), source.size(), os_error);
            return finish_patch(status, os_error, "memory::write_bytes", address, source.size(), fast_status);
        }

        Result<void> patch_code(Address address, std::span<const std::byte> source) noexcept
        {
            // Same validation order as write_bytes.
            if (!address)
            {
                return std::unexpected(Error{ErrorCode::NullTargetAddress, "memory::patch_code", address.raw(), 0});
            }
            if (source.data() == nullptr && !source.empty())
            {
                return std::unexpected(Error{ErrorCode::NullSourceBytes, "memory::patch_code", address.raw(), 0});
            }
            if (source.empty())
            {
                return {};
            }
            if (source.size() > MAX_WRITE_SIZE)
            {
                return std::unexpected(Error{ErrorCode::SizeTooLarge, "memory::patch_code", address.raw(), 0});
            }
            if (span_overlaps_target(address, source.data(), source.size()))
            {
                return std::unexpected(Error{ErrorCode::OverlappingRanges, "memory::patch_code", address.raw(), 0});
            }

            // Fast path: the target is already writable, so the store changes no protection. Unlike write_bytes,
            // patch_code then flushes the instruction cache so an already-writable code patch is visible to execution.
            // No protection changed, so nothing is invalidated in the protection cache.
            const detail::GuardedWriteStatus fast_status =
                detail::guarded_write_bytes(address.raw(), source.data(), source.size());
            if (fast_status == detail::GuardedWriteStatus::Ok)
            {
                if (!detail::flush_instruction_cache(address.raw(), source.size()))
                {
                    return std::unexpected(
                        Error{ErrorCode::InstructionFlushFailed, "memory::patch_code", address.raw(), 0}
                    );
                }
                return {};
            }

            if (fast_status == detail::GuardedWriteStatus::MayBePartial)
            {
                // The copy order is unspecified outside the deterministic test seam, so flush the full request before
                // fallback setup can fail. A partial-write or restoration error outranks this best-effort flush.
                (void)detail::flush_instruction_cache(address.raw(), source.size());
            }

            // Slow path: unprotect (execute preserved for a code region), write, flush executable regions, restore.
            std::uint32_t os_error = 0;
            const detail::PatchStatus status =
                detail::patch_bytes(address.raw(), source.data(), source.size(), os_error, true);
            return finish_patch(status, os_error, "memory::patch_code", address, source.size(), fast_status);
        }

        Result<void> write_in_place(Address address, std::span<const std::byte> source) noexcept
        {
            // Same validation order as write_bytes: a null target outranks a null source, and a zero-length write is a
            // success no-op that inspects neither the source pointer nor the target's protection.
            if (!address)
            {
                return std::unexpected(Error{ErrorCode::NullTargetAddress, "memory::write_in_place", address.raw(), 0});
            }
            if (source.data() == nullptr && !source.empty())
            {
                return std::unexpected(Error{ErrorCode::NullSourceBytes, "memory::write_in_place", address.raw(), 0});
            }
            if (source.empty())
            {
                return {};
            }
            // Cap oversized spans for parity with write_bytes: the guarded copy already fails closed at the first
            // unwritable page, so this is an API-symmetry guard that rejects an obviously-wrong length up front with
            // the same ErrorCode::SizeTooLarge rather than attempting a multi-gigabyte guarded copy.
            if (source.size() > MAX_WRITE_SIZE)
            {
                return std::unexpected(Error{ErrorCode::SizeTooLarge, "memory::write_in_place", address.raw(), 0});
            }
            if (span_overlaps_target(address, source.data(), source.size()))
            {
                return std::unexpected(Error{ErrorCode::OverlappingRanges, "memory::write_in_place", address.raw(), 0});
            }

            // The strict path: a guarded write that changes NO protection. A read-only, executable, or no-access target
            // faults the guarded copy and fails closed. This entry point exists precisely to reject a write the
            // caller did not intend to escalate, so it never reaches the VirtualProtect dance write_bytes takes on a
            // fault. No cache invalidation either: changing nothing leaves the cached protection state valid.
            const detail::GuardedWriteStatus status =
                detail::guarded_write_bytes(address.raw(), source.data(), source.size());
            if (status == detail::GuardedWriteStatus::Ok)
            {
                return {};
            }

            if (status == detail::GuardedWriteStatus::MayBePartial)
            {
                return std::unexpected(Error{ErrorCode::WriteMayBePartial, "memory::write_in_place", address.raw(), 0});
            }
            return std::unexpected(Error{ErrorCode::WriteFaulted, "memory::write_in_place", address.raw(), 0});
        }

        Result<Address> walk(Address base, std::span<const ChainStep> steps, std::span<Address> trace) noexcept
        {
            // A null root cannot be dereferenced. An empty chain is the identity walk (engine returns base), so the
            // null root is only an error when there is at least one hop to take.
            if (!base && !steps.empty())
            {
                return std::unexpected(Error{ErrorCode::NullChain, "memory::walk", 0, 0});
            }

            const detail::ChainWalkOutcome outcome =
                detail::guarded_resolve_chain(base, steps.data(), steps.size(), trace.data(), trace.size());
            if (!outcome.ok)
            {
                // ReadFaulted carries the failing hop index in Error::detail: the hop whose dereference faulted, or
                // whose dereferenced link fell below that hop's plausibility floor.
                return std::unexpected(Error{ErrorCode::ReadFaulted, "memory::walk", outcome.fail_index, 0});
            }
            return outcome.address;
        }

        Result<Address> walk(Address base, std::span<const std::ptrdiff_t> offsets, std::span<Address> trace) noexcept
        {
            // The bare-offset chain applies the default plausibility floor to every hop, so it is the ChainStep walk
            // with every min_valid defaulted. This overload is documented callback-safe (allocation-free), so it must
            // build the ChainStep view on a fixed stack buffer and never touch the heap: a chain longer than the inline
            // bound fails closed with SizeTooLarge rather than allocating a std::vector (which would contradict the
            // allocation-free label and, on OOM, force a bad_alloc catch on a hot path). A caller with a genuinely
            // long chain is steered to the ChainStep-taking overload above, where the caller owns the step storage.
            constexpr std::size_t inline_capacity = 32;
            if (offsets.size() > inline_capacity)
            {
                return std::unexpected(Error{ErrorCode::SizeTooLarge, "memory::walk", offsets.size(), inline_capacity});
            }
            std::array<ChainStep, inline_capacity> steps{};
            for (std::size_t i = 0; i < offsets.size(); ++i)
            {
                steps[i] = ChainStep{offsets[i]};
            }
            return walk(base, std::span<const ChainStep>{steps.data(), offsets.size()}, trace);
        }
    } // namespace memory
} // namespace DetourModKit
