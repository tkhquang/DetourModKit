#ifndef DETOURMODKIT_ADDRESS_HPP
#define DETOURMODKIT_ADDRESS_HPP

/**
 * @file address.hpp
 * @brief The Address value type, the single addressing vocabulary of the public surface.
 * @details Only `rip()` reads process memory. Only the pointer constructor, `as<T>()`, `ptr<T>()`, and `rip()` cast
 *          between an integer and a pointer.
 */

#include "DetourModKit/defines.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace DetourModKit
{
    /**
     * @brief A strongly-typed machine address with constexpr arithmetic and an explicit cast surface.
     * @details Address is trivially copyable and exactly one machine pointer in size and alignment.
     */
    class Address
    {
        std::uintptr_t m_value{0};

    public:
        /// Constructs a null address (numeric value zero).
        constexpr Address() noexcept = default;

        /** @brief Constructs from a raw numeric address. */
        constexpr explicit Address(std::uintptr_t value) noexcept : m_value{value} {}

        /** @brief Constructs a null address from `nullptr`. */
        constexpr Address(std::nullptr_t) noexcept : m_value{0} {}

        /** @brief Constructs from any object or function pointer. */
        template <class T> explicit Address(T *pointer) noexcept : m_value{reinterpret_cast<std::uintptr_t>(pointer)} {}

        /// Returns the underlying numeric address.
        [[nodiscard]] constexpr std::uintptr_t raw() const noexcept { return m_value; }

        /// Tests whether the address is non-null.
        [[nodiscard]] constexpr explicit operator bool() const noexcept { return m_value != 0; }

        /**
         * @brief Returns this address advanced by a signed byte delta.
         * @details The arithmetic wraps modulo 2^64, so a negative delta moves backward. A null base is also valid.
         */
        [[nodiscard]] constexpr Address offset(std::ptrdiff_t delta) const noexcept
        {
            return Address{m_value + static_cast<std::uintptr_t>(delta)};
        }

        /**
         * @brief Returns this address rounded up to a multiple of @p alignment.
         * @param alignment A power of two in bytes. Any other value yields a meaningless result, not a diagnostic.
         * @details An address within `alignment - 1` bytes of the address-space top wraps modulo 2^64, so the result
         *          is then numerically below this address.
         */
        [[nodiscard]] constexpr Address align_up(std::size_t alignment) const noexcept
        {
            const std::uintptr_t mask = static_cast<std::uintptr_t>(alignment) - 1U;
            return Address{(m_value + mask) & ~mask};
        }

        /**
         * @brief Resolves a RIP-relative reference whose displacement is embedded in the instruction at this address.
         * @param displacement_at Byte offset from this address to the signed 4-byte displacement field.
         * @param instruction_length Total length of the instruction in bytes.
         * @return The absolute target: (this + instruction_length) + sign-extended disp32.
         * @details The read is unchecked. Use it only for a located and validated instruction whose bytes are mapped.
         *          For a guarded read, use scan::resolve_rip_relative().
         */
        [[nodiscard]] Address rip(std::ptrdiff_t displacement_at, std::size_t instruction_length) const noexcept
        {
            // The disp32 field is rarely 4-byte aligned, so memcpy is the defined unaligned load.
            std::int32_t displacement = 0;
            std::memcpy(
                &displacement,
                reinterpret_cast<const void *>(m_value + static_cast<std::uintptr_t>(displacement_at)),
                sizeof(displacement)
            );
            const std::uintptr_t next_instruction = m_value + static_cast<std::uintptr_t>(instruction_length);
            return Address{next_instruction + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement))};
        }

        /**
         * @brief Reinterprets the address as a value of type @p T.
         * @tparam T A pointer type, or an integral type at least as wide as `std::uintptr_t`. For a narrower integer,
         *           use @ref raw(). For a typed view of the addressed bytes, use @ref ptr().
         * @note Callback-safe: a pure cast, with no allocation, lock, or I/O.
         */
        template <class T>
            requires(std::is_pointer_v<T> || (std::is_integral_v<T> && sizeof(T) >= sizeof(std::uintptr_t)))
        [[nodiscard]] T as() const noexcept
        {
            if constexpr (std::is_integral_v<T>)
            {
                return static_cast<T>(m_value);
            }
            else
            {
                return reinterpret_cast<T>(m_value);
            }
        }

        /// Reinterprets the address as a `T*`, the shorthand for `as<T*>()`.
        template <class T> [[nodiscard]] T *ptr() const noexcept { return reinterpret_cast<T *>(m_value); }

        /// Orders and compares addresses by their numeric value.
        [[nodiscard]] constexpr auto operator<=>(const Address &) const noexcept = default;
        [[nodiscard]] constexpr bool operator==(const Address &) const noexcept = default;
    };

    static_assert(
        sizeof(Address) == sizeof(void *) && alignof(Address) == alignof(void *),
        "Address must be exactly a machine pointer in size and alignment."
    );
    static_assert(std::is_trivially_copyable_v<Address>, "Address must stay trivially copyable.");

} // namespace DetourModKit

#endif // DETOURMODKIT_ADDRESS_HPP
