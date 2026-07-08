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
#include <new>
#include <span>
#include <vector>

namespace DetourModKit
{
    namespace memory
    {
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
            if (detail::guarded_write_bytes(address.raw(), source.data(), source.size()))
            {
                return {};
            }

            // Slow path: the target was read-only or executable, so the engine changes protection, writes, flushes the
            // instruction cache, and restores. Every slow-path exit touched protection (a failed change still rolled
            // back regions it had already flipped), so invalidate the range on all of them so a snapshot a concurrent
            // reader cached from the transient protection cannot survive.
            std::uint32_t os_error = 0;
            const detail::PatchStatus status =
                detail::patch_bytes(address.raw(), source.data(), source.size(), os_error);
            switch (status)
            {
            case detail::PatchStatus::Ok:
                invalidate_range(Region{address, source.size()});
                return {};
            case detail::PatchStatus::WriteFaulted:
                // The slow path changed protection (so a cached entry may describe the pre-change state) but the
                // guarded copy faulted; the engine has already restored the original protection and flushed. Invalidate
                // the range and fail closed rather than reporting a write that did not complete.
                invalidate_range(Region{address, source.size()});
                return std::unexpected(Error{ErrorCode::WriteFaulted, "memory::write_bytes", address.raw(), 0});
            case detail::PatchStatus::ProtectionRestoreFailed:
                invalidate_range(Region{address, source.size()});
                return std::unexpected(
                    Error{ErrorCode::ProtectionRestoreFailed, "memory::write_bytes", address.raw(), os_error});
            case detail::PatchStatus::ProtectionChangeFailed:
            default:
                invalidate_range(Region{address, source.size()});
                return std::unexpected(
                    Error{ErrorCode::ProtectionChangeFailed, "memory::write_bytes", address.raw(), os_error});
            }
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
            if (!detail::guarded_write_bytes(address.raw(), source.data(), source.size()))
            {
                return std::unexpected(Error{ErrorCode::WriteFaulted, "memory::write_in_place", address.raw(), 0});
            }
            return {};
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
            // with every min_valid defaulted. Build the ChainStep view on the stack for the short chains that dominate
            // real pointer paths; fall back to the heap only for an unusually long chain, mapping an allocation failure
            // onto OutOfMemory so this noexcept entry point never lets bad_alloc escape.
            constexpr std::size_t inline_capacity = 32;
            if (offsets.size() <= inline_capacity)
            {
                std::array<ChainStep, inline_capacity> steps{};
                for (std::size_t i = 0; i < offsets.size(); ++i)
                {
                    steps[i] = ChainStep{offsets[i]};
                }
                return walk(base, std::span<const ChainStep>{steps.data(), offsets.size()}, trace);
            }

            try
            {
                std::vector<ChainStep> steps;
                steps.reserve(offsets.size());
                for (const std::ptrdiff_t offset : offsets)
                {
                    steps.push_back(ChainStep{offset});
                }
                return walk(base, std::span<const ChainStep>{steps}, trace);
            }
            catch (const std::bad_alloc &)
            {
                return std::unexpected(Error{ErrorCode::OutOfMemory, "memory::walk"});
            }
        }
    } // namespace memory
} // namespace DetourModKit
