/**
 * @file scan_rip_relative.cpp
 * @brief Standalone x86-64 RIP-relative resolvers: resolve_rip_relative() and find_and_resolve_rip_relative().
 * @details Resolves an absolute address from a RIP-relative instruction whose displacement is read under an SEH fault
 *          guard, then screened against the plausible-userspace floor. find_and_resolve_rip_relative scans a Region for
 *          an opcode prefix (first-prefix-wins) and resolves the disp32 assumed to follow it. Both express the legacy
 *          scanner logic verbatim in the Address / Region / Result vocabulary, mapping the former RipResolveError set to
 *          the unified ErrorCode Scan block.
 */

#include "DetourModKit/scan.hpp"

#include "DetourModKit/memory.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace DetourModKit
{
    namespace scan
    {
        Result<Address> resolve_rip_relative(Address instruction, std::size_t displacement_offset,
                                             std::size_t instruction_length) noexcept
        {
            if (!instruction)
            {
                return std::unexpected(Error{ErrorCode::NullInput, "scan::resolve_rip_relative"});
            }

            const std::uintptr_t base = instruction.raw();
            const std::uintptr_t disp_addr = base + static_cast<std::uintptr_t>(displacement_offset);
            // Read the displacement under a single SEH fault guard instead of is_readable + raw memcpy. is_readable is
            // a time-of-check/time-of-use illusion -- the page can change protection or unmap between the check and the
            // copy -- so an unguarded memcpy could fault the host.
            const auto displacement = Memory::seh_read<std::int32_t>(disp_addr);
            if (!displacement)
            {
                return std::unexpected(Error{ErrorCode::UnreadableDisplacement, "scan::resolve_rip_relative"});
            }

            // Compute the target in unsigned modular arithmetic so the math stays well-defined on every input,
            // including kernel-range instruction addresses (where intptr_t would be negative and signed overflow is
            // UB). The displacement is sign-extended first so negative disp32 values wrap to the correct 64-bit offset.
            const std::uintptr_t disp_sext = static_cast<std::uintptr_t>(static_cast<std::int64_t>(*displacement));
            const std::uintptr_t target = base + instruction_length + disp_sext;

            // Fail closed on a target that cannot be a real in-process address. A corrupt or hostile displacement can
            // resolve to 0, a low guard-page address, or a kernel-range value; returning that as "success" would hand
            // the caller a pointer that faults on first use. plausible_userspace_ptr is pure arithmetic, so this guard
            // adds no syscall and no memory access.
            if (!Memory::plausible_userspace_ptr(target))
            {
                return std::unexpected(Error{ErrorCode::ImplausibleTarget, "scan::resolve_rip_relative"});
            }
            return Address{target};
        }

        Result<Address> find_and_resolve_rip_relative(Region search, std::span<const std::byte> opcode_prefix,
                                                      std::size_t instruction_length) noexcept
        {
            const std::byte *search_start = search.base.ptr<const std::byte>();
            if (!search_start || opcode_prefix.empty())
            {
                return std::unexpected(Error{ErrorCode::NullInput, "scan::find_and_resolve_rip_relative"});
            }

            const std::size_t prefix_len = opcode_prefix.size();
            const std::size_t min_bytes = prefix_len + sizeof(std::int32_t);
            if (search.size < min_bytes)
            {
                return std::unexpected(Error{ErrorCode::RegionTooSmall, "scan::find_and_resolve_rip_relative"});
            }

            const std::size_t scan_limit = search.size - min_bytes;
            const std::byte first = opcode_prefix[0];

            for (std::size_t i = 0; i <= scan_limit; ++i)
            {
                if (search_start[i] != first)
                {
                    continue;
                }

                if (prefix_len > 1 && std::memcmp(&search_start[i + 1], opcode_prefix.data() + 1, prefix_len - 1) != 0)
                {
                    continue;
                }

                return resolve_rip_relative(Address{&search_start[i]}, prefix_len, instruction_length);
            }

            return std::unexpected(Error{ErrorCode::PrefixNotFound, "scan::find_and_resolve_rip_relative"});
        }
    } // namespace scan
} // namespace DetourModKit
