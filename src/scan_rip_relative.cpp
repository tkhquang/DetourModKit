/**
 * @file scan_rip_relative.cpp
 * @brief Standalone x86-64 RIP-relative resolvers and candidate semantic verification.
 * @details Resolves an absolute address from a RIP-relative instruction whose displacement is read under a fault guard,
 *          then screened against the plausible-userspace floor. find_and_resolve_rip_relative scans a Region for an
 *          opcode prefix and returns the first occurrence whose disp32 resolves plausibly, skipping decoy prefixes
 *          whose displacement cannot be trusted. A failure on either path surfaces as a typed ErrorCode in the Scan
 *          block rather than undefined behaviour.
 */

#include "DetourModKit/scan.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/scan_shared.hpp"

#include <Zydis/Zydis.h>

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
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
            if (!is_valid_rip_relative_layout(displacement_offset, instruction_length))
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "scan::resolve_rip_relative"});
            }

            const std::uintptr_t base = instruction.raw();
            const std::uintptr_t disp_addr = base + static_cast<std::uintptr_t>(displacement_offset);
            // Read the displacement under one fault guard instead of is_readable + raw memcpy. is_readable is
            // a time-of-check/time-of-use illusion -- the page can change protection or unmap between the check and the
            // copy -- so an unguarded memcpy could fault the host.
            const auto displacement = detail::guarded_read<std::int32_t>(disp_addr);
            if (!displacement)
            {
                return std::unexpected(Error{ErrorCode::UnreadableDisplacement, "scan::resolve_rip_relative"});
            }

            // Compute the target in unsigned modular arithmetic so the math stays well-defined on every input,
            // including kernel-range instruction addresses (where intptr_t would be negative and signed overflow is
            // UB). The displacement is sign-extended first so negative disp32 values wrap to the correct 64-bit offset.
            const std::uintptr_t target = detail::add_rip_displacement(base, instruction_length, *displacement);

            // Fail closed on a target that cannot be a real in-process address. A corrupt or hostile displacement can
            // resolve to 0, a low guard-page address, or a kernel-range value; returning that as "success" would hand
            // the caller a pointer that faults on first use. is_plausible_ptr is pure arithmetic, so this guard
            // adds no syscall and no memory access.
            if (!detail::is_plausible_ptr(target))
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
            if (!is_valid_rip_relative_layout(prefix_len, instruction_length))
            {
                return std::unexpected(Error{ErrorCode::InvalidArg, "scan::find_and_resolve_rip_relative"});
            }
            const std::size_t min_bytes = prefix_len + sizeof(std::int32_t);
            if (search.size < min_bytes)
            {
                return std::unexpected(Error{ErrorCode::RegionTooSmall, "scan::find_and_resolve_rip_relative"});
            }

            const std::size_t scan_limit = search.size - min_bytes;
            const std::byte first = opcode_prefix[0];

            // A byte sequence that matches the opcode prefix but whose disp32 resolves to an
            // implausible target (or is unreadable) is a decoy, not a hard stop: the same prefix
            // can legitimately recur, so the genuine instruction may be a later occurrence. Keep
            // scanning past each decoy and return the first occurrence whose displacement resolves
            // plausibly. The last resolve failure is retained so an all-decoy region reports WHY
            // resolution never succeeded (e.g. ImplausibleTarget) rather than a bare PrefixNotFound.
            std::optional<Error> last_resolve_error;

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

                auto resolved = resolve_rip_relative(Address{&search_start[i]}, prefix_len, instruction_length);
                if (resolved)
                {
                    return resolved;
                }
                last_resolve_error = resolved.error();
            }

            // A prefix was found but no occurrence resolved: surface the concrete decode failure.
            if (last_resolve_error)
            {
                return std::unexpected(*last_resolve_error);
            }
            return std::unexpected(Error{ErrorCode::PrefixNotFound, "scan::find_and_resolve_rip_relative"});
        }
    } // namespace scan

    namespace detail
    {
        std::optional<std::int32_t> decode_rip_displacement(std::uintptr_t match, std::size_t displacement_offset,
                                                            std::size_t instruction_length) noexcept
        {
            if (!scan::is_valid_rip_relative_layout(displacement_offset, instruction_length))
            {
                return std::nullopt;
            }

            // Read exactly the declared instruction, while also refusing a declaration that crosses a live image end.
            // Reading a maximum-length window would reject a valid instruction at a page boundary merely because bytes
            // after the instruction are inaccessible.
            HMODULE owning_module = nullptr;
            Region live_image;
            if (::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                     reinterpret_cast<LPCWSTR>(match), &owning_module) &&
                owning_module != nullptr)
            {
                live_image = module_image_region(Address{owning_module});
            }
            const ModuleSpan image = module_span(live_image);
            if (image.valid() && match >= image.base && match < image.end)
            {
                const std::uintptr_t to_end = image.end - match;
                if (to_end < instruction_length)
                {
                    return std::nullopt;
                }
            }
            std::byte window[ZYDIS_MAX_INSTRUCTION_LENGTH]{};
            if (!guarded_read_bytes(match, window, instruction_length))
            {
                return std::nullopt;
            }

            ZydisDecoder decoder;
            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
            {
                return std::nullopt;
            }
            ZydisDecodedInstruction instruction;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, window, instruction_length, &instruction, operands)))
            {
                return std::nullopt;
            }

            // The resolution computes (match + instruction_length + disp), so the declared length must be the true
            // encoded length or the next-instruction anchor drifts, and the declared field must be a disp32 at exactly
            // the declared offset.
            if (instruction.length != instruction_length)
            {
                return std::nullopt;
            }
            if (instruction.raw.disp.size != 32 || instruction.raw.disp.offset != displacement_offset)
            {
                return std::nullopt;
            }
            // The disp32 must belong to a RIP-relative memory operand: a same-offset disp32 on an absolute or
            // SIB-indexed operand is not the reference the metadata resolves.
            for (std::size_t i = 0; i < instruction.operand_count_visible; ++i)
            {
                const ZydisDecodedOperand &operand = operands[i];
                if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP &&
                    operand.mem.disp.has_displacement)
                {
                    std::int32_t displacement = 0;
                    std::memcpy(&displacement, window + displacement_offset, sizeof(displacement));
                    return displacement;
                }
            }
            return std::nullopt;
        }
    } // namespace detail
} // namespace DetourModKit
