#ifndef DETOURMODKIT_X86_DECODE_HPP
#define DETOURMODKIT_X86_DECODE_HPP

#include "DetourModKit/memory.hpp"

#include <cstdint>
#include <cstring>
#include <optional>

namespace DetourModKit::detail
{
    [[nodiscard]] inline std::optional<std::uintptr_t>
    decode_e9_rel32(std::uintptr_t address) noexcept
    {
        if (!Memory::is_readable(reinterpret_cast<const void *>(address), 5))
        {
            return std::nullopt;
        }
        const auto *bytes = reinterpret_cast<const std::uint8_t *>(address);
        if (bytes[0] != 0xE9)
        {
            return std::nullopt;
        }
        std::int32_t disp = 0;
        std::memcpy(&disp, bytes + 1, sizeof(disp));
        return static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(address) + 5 + disp);
    }

    [[nodiscard]] inline std::optional<std::uintptr_t>
    decode_eb_rel8(std::uintptr_t address) noexcept
    {
        if (!Memory::is_readable(reinterpret_cast<const void *>(address), 2))
        {
            return std::nullopt;
        }
        const auto *bytes = reinterpret_cast<const std::uint8_t *>(address);
        if (bytes[0] != 0xEB)
        {
            return std::nullopt;
        }
        const auto disp = static_cast<std::int8_t>(bytes[1]);
        return static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(address) + 2 + disp);
    }

    [[nodiscard]] inline std::optional<std::uintptr_t>
    decode_ff25_indirect(std::uintptr_t address) noexcept
    {
        if (!Memory::is_readable(reinterpret_cast<const void *>(address), 6))
        {
            return std::nullopt;
        }
        const auto *bytes = reinterpret_cast<const std::uint8_t *>(address);
        if (bytes[0] != 0xFF || bytes[1] != 0x25)
        {
            return std::nullopt;
        }
        std::int32_t disp = 0;
        std::memcpy(&disp, bytes + 2, sizeof(disp));
        const auto slot_addr = static_cast<std::uintptr_t>(
            static_cast<std::int64_t>(address) + 6 + disp);
        if (!Memory::is_readable(reinterpret_cast<const void *>(slot_addr), sizeof(std::uintptr_t)))
        {
            return std::nullopt;
        }
        std::uintptr_t indirect_destination = 0;
        std::memcpy(&indirect_destination,
                    reinterpret_cast<const void *>(slot_addr),
                    sizeof(indirect_destination));
        return indirect_destination;
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_X86_DECODE_HPP
