#ifndef DETOURMODKIT_X86_DECODE_HPP
#define DETOURMODKIT_X86_DECODE_HPP

#include "DetourModKit/memory.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

namespace DetourModKit::detail
{
    // Each decoder copies the candidate instruction bytes into a local buffer
    // under a single SEH fault guard (seh_read_bytes), then inspects the copy.
    // Read-then-test on a local buffer closes the time-of-check to time-of-use
    // gap that is_readable + a raw dereference leaves open: the target page can
    // change protection or unmap between the probe and the access, and these
    // decoders run on the nested-hook detection and prologue-recovery paths
    // where the page state is most likely to be in flux. A faulting read
    // returns nullopt rather than taking down the host.

    [[nodiscard]] inline std::optional<std::uintptr_t>
    decode_e9_rel32(std::uintptr_t address) noexcept
    {
        std::array<std::uint8_t, 5> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        if (code[0] != 0xE9)
        {
            return std::nullopt;
        }
        std::int32_t disp = 0;
        std::memcpy(&disp, code.data() + 1, sizeof(disp));
        return static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(address) + 5 + disp);
    }

    [[nodiscard]] inline std::optional<std::uintptr_t>
    decode_eb_rel8(std::uintptr_t address) noexcept
    {
        std::array<std::uint8_t, 2> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        if (code[0] != 0xEB)
        {
            return std::nullopt;
        }
        const auto disp = static_cast<std::int8_t>(code[1]);
        return static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(address) + 2 + disp);
    }

    // FF 25 disp32 on x86-64 is RIP-relative: the 32-bit signed displacement
    // is added to the address of the next instruction. On x86 (32-bit) the
    // same encoding is absolute, which this decoder does not handle.
    [[nodiscard]] inline std::optional<std::uintptr_t>
    decode_ff25_indirect(std::uintptr_t address) noexcept
    {
        static_assert(sizeof(void *) == 8,
                      "decode_ff25_indirect assumes x86-64 RIP-relative semantics");
        std::array<std::uint8_t, 6> code{};
        if (!Memory::seh_read_bytes(address, code.data(), code.size()))
        {
            return std::nullopt;
        }
        if (code[0] != 0xFF || code[1] != 0x25)
        {
            return std::nullopt;
        }
        std::int32_t disp = 0;
        std::memcpy(&disp, code.data() + 2, sizeof(disp));
        const auto slot_addr = static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(address) + 6 + disp);
        // The slot stores the final indirect target; read it under the same
        // fault guard rather than is_readable + a raw dereference.
        const auto indirect_destination = Memory::seh_read<std::uintptr_t>(slot_addr);
        if (!indirect_destination)
        {
            return std::nullopt;
        }
        return *indirect_destination;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_X86_DECODE_HPP
