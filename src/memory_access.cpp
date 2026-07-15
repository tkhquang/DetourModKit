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
#include <span>

namespace DetourModKit
{
    namespace memory
    {
        namespace
        {
            // Maps a protection-changing patch outcome onto the public Result, invalidating the cached protection for
            // the touched range on every exit (every slow-path exit changed protection, and a failed change still
            // rolled back regions it had already flipped, so a snapshot a concurrent reader cached from the transient
            // protection must not survive). Shared by write_bytes and patch_code.
            [[nodiscard]] Result<void> finish_patch(detail::PatchStatus status, std::uint32_t os_error,
                                                    const char *where, Address address, std::size_t size,
                                                    detail::GuardedWriteStatus fast_status) noexcept
            {
                invalidate_range(Region{address, size});
                switch (status)
                {
                case detail::PatchStatus::Ok:
                    return {};
                case detail::PatchStatus::WriteMayBePartial:
                    return std::unexpected(Error{ErrorCode::WriteMayBePartial, where, address.raw(), 0});
                case detail::PatchStatus::WriteFaulted:
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
            if (!detail::guarded_read_bytes(address.raw(), out.data(), out.size()))
            {
                return std::unexpected(Error{ErrorCode::ReadFaulted, "memory::read_into", address.raw(), 0});
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

            // Fast path: a guarded write that changes no protection. It succeeds for an already-writable target -- a
            // live game field, or any page held writable by a ProtectGuard -- with no VirtualProtect and no flush, so a
            // per-frame writer stays off the syscall path.
            const detail::GuardedWriteStatus fast_status =
                detail::guarded_write_bytes(address.raw(), source.data(), source.size());
            if (fast_status == detail::GuardedWriteStatus::Ok)
            {
                return {};
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
                        Error{ErrorCode::InstructionFlushFailed, "memory::patch_code", address.raw(), 0});
                }
                return {};
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

            // The strict path: a guarded write that changes NO protection. A read-only, executable, or no-access target
            // faults the guarded copy and fails closed -- this entry point exists precisely to reject a write the
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
