#ifndef DETOURMODKIT_ADDRESS_HPP
#define DETOURMODKIT_ADDRESS_HPP

/**
 * @file address.hpp
 * @brief The Address value type -- the single addressing vocabulary for the v4 surface.
 * @details v3 passed locations around as bare `std::uintptr_t` and reinterpret_cast at every use site, which scattered
 *          the one genuinely unsafe operation (integer <-> pointer punning) across the whole codebase and made
 *          "is this number a pointer, an offset, or a size?" a matter of reading the variable name. Address replaces
 *          that with a zero-overhead strong type: it is exactly a machine pointer wide (asserted below), every
 *          arithmetic helper is `constexpr`, and the reinterpret_cast story is confined to the four audited members
 *          (the templated pointer constructor, `as<T>()`, `ptr<T>()`, and the RIP-relative read in `rip()`).
 *          Everything else is plain integer math on a value that cannot be silently confused with an int.
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
     * @class Address
     * @brief A strongly-typed machine address with constexpr arithmetic and a single audited cast surface.
     * @details Constructs from a raw integer, from `nullptr`, or from any object/function pointer, and converts back
     *          out only through the explicit `as<T>()` / `ptr<T>()` accessors. Comparisons and the boolean test follow
     *          pointer intuition (null is false; ordering is by numeric address). The type is trivially copyable and
     *          occupies exactly one pointer, so it is free to pass by value and to store in the scan/hook result
     *          structs without any layout cost over the old `uintptr_t`.
     */
    class Address
    {
        std::uintptr_t m_value{0};

    public:
        /// Constructs a null address (numeric value zero).
        constexpr Address() noexcept = default;

        /**
         * @brief Constructs from a raw integral address.
         * @param value The numeric address.
         * @details Explicit so an arbitrary integer never silently becomes an Address; this is the canonical entry
         *          point for an address that arrives as a number (a scan hit, a serialized offset applied to a base).
         */
        constexpr explicit Address(std::uintptr_t value) noexcept : m_value{value} {}

        /**
         * @brief Constructs a null address from `nullptr`.
         * @details A dedicated overload so `Address{nullptr}` is well-formed: the templated pointer constructor below
         *          does not bind `std::nullptr_t` (it has no pointee type to deduce), so without this overload the
         *          literal would be ambiguous or ill-formed.
         */
        constexpr Address(std::nullptr_t) noexcept : m_value{0} {}

        /**
         * @brief Constructs from any object or function pointer.
         * @tparam T The pointee type, deduced from the argument.
         * @param pointer The pointer to capture as an address.
         * @details The `T*` parameter only deduces against an actual pointer argument, so a non-pointer is a deduction
         *          failure and never competes here, and `std::nullptr_t` is taken by the overload above. That keeps
         *          this one of the four audited reinterpret_cast sites instead of letting pointer punning leak to
         *          call sites.
         */
        template <class T> explicit Address(T *pointer) noexcept : m_value{reinterpret_cast<std::uintptr_t>(pointer)} {}

        /// Returns the underlying numeric address.
        [[nodiscard]] constexpr std::uintptr_t raw() const noexcept { return m_value; }

        /// Tests whether the address is non-null, matching pointer truthiness; explicit to avoid accidental int use.
        [[nodiscard]] constexpr explicit operator bool() const noexcept { return m_value != 0; }

        /**
         * @brief Returns this address advanced by a signed byte delta.
         * @param delta The byte offset to add (may be negative).
         * @details Wrapping unsigned arithmetic, so a negative delta walks backwards without invoking signed overflow.
         *          Pure value math: it never dereferences, so it is valid on any address including a null base used as
         *          an offset origin.
         */
        [[nodiscard]] constexpr Address offset(std::ptrdiff_t delta) const noexcept
        {
            return Address{m_value + static_cast<std::uintptr_t>(delta)};
        }

        /**
         * @brief Returns this address rounded up to the next multiple of @p alignment.
         * @param alignment The alignment in bytes; must be a power of two.
         * @details Branch-free power-of-two round-up. The caller owns the power-of-two precondition (an alignment of 0
         *          or a non-power-of-two yields a meaningless result rather than a diagnostic), matching how alignment
         *          helpers are used on the scan/page paths where the value is always a known constant.
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
         * @details This is the RAW, unchecked resolve used once an instruction has already been located and validated;
         *          it reads the disp32 straight out of process memory and assumes the bytes are mapped. The
         *          bounds-checked, fault-tolerant resolver that probes readability first lives in the scan/memory
         *          layer -- this member is the arithmetic core it builds on, kept here so the x86-64 RIP-relative
         *          convention (the displacement is measured from the END of the instruction, i.e. the next IP) is
         *          expressed in exactly one place.
         */
        [[nodiscard]] Address rip(std::ptrdiff_t displacement_at, std::size_t instruction_length) const noexcept
        {
            // Load the disp32 with memcpy rather than a typed dereference. A displacement field sits at an arbitrary
            // byte offset inside an instruction and is almost never 4-byte aligned, so forming an `int32_t *` to it
            // and dereferencing would be undefined behaviour. memcpy of a fixed 4 bytes is the well-defined unaligned
            // load and the compiler folds it to a single (unaligned) mov on x86-64.
            std::int32_t displacement = 0;
            std::memcpy(&displacement,
                        reinterpret_cast<const void *>(m_value + static_cast<std::uintptr_t>(displacement_at)),
                        sizeof(displacement));
            const std::uintptr_t next_instruction = m_value + static_cast<std::uintptr_t>(instruction_length);
            return Address{next_instruction + static_cast<std::uintptr_t>(static_cast<std::intptr_t>(displacement))};
        }

        /**
         * @brief Reinterprets the address as a value of type @p T.
         * @tparam T A pointer / function-pointer type, or a pointer-width integer (`std::uintptr_t`, `std::intptr_t`,
         *          and same-width aliases such as `std::size_t`). Narrower integrals, references, and non-pointer
         *          object types are rejected by the constraint below.
         * @details The `requires` clause matches the two casts this accessor performs:
         *          - A pointer or function-pointer @p T takes the `reinterpret_cast` path -- the pointer pun that turns
         *            a resolved address back into a typed function pointer to call or a typed data pointer to read,
         *            kept confined to this one member instead of scattered across call sites.
         *          - An integral @p T takes the `static_cast` path. The width constraint prevents truncating the
         *            pointer-sized representation; a narrower integral such as `int` is a compile error here instead
         *            of a lossy conversion that reads like a safe address cast.
         *          A reference @p T is excluded on purpose: it would reinterpret this Address object's own storage (a
         *          pun on the handle, never on the memory it names), which is a bug at every call site. A caller that
         *          deliberately wants a narrowed integer takes it explicitly from @ref raw(); a caller that wants a
         *          typed view of the addressed bytes uses @ref ptr() (or `as<T*>()`) and dereferences.
         * @note Callback-safe: a pure cast, no allocation, locking, or I/O.
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

        /// Reinterprets the address as a `T*`; the typed-pointer shorthand for `as<T*>()`.
        template <class T> [[nodiscard]] T *ptr() const noexcept { return reinterpret_cast<T *>(m_value); }

        /// Numeric three-way ordering, so `<`, `<=`, `==`, ... all compare by raw address.
        [[nodiscard]] constexpr auto operator<=>(const Address &) const noexcept = default;
        [[nodiscard]] constexpr bool operator==(const Address &) const noexcept = default;
    };

    // An Address must be a drop-in, zero-cost replacement for a raw pointer everywhere it is passed or stored; if it
    // ever grew past a machine pointer the "free to pass by value" assumption and the reinterpret_cast round-trips
    // would both break. Pin it at compile time.
    static_assert(sizeof(Address) == sizeof(void *) && alignof(Address) == alignof(void *),
                  "Address must be exactly a machine pointer in size and alignment.");
    static_assert(std::is_trivially_copyable_v<Address>, "Address must stay trivially copyable.");

} // namespace DetourModKit

#endif // DETOURMODKIT_ADDRESS_HPP
