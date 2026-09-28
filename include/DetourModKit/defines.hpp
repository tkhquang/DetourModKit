#ifndef DETOURMODKIT_DEFINES_HPP
#define DETOURMODKIT_DEFINES_HPP

/**
 * @file defines.hpp
 * @brief Single home for every cross-compiler portability primitive in DetourModKit.
 */

#include <type_traits>

// The empty block declares the primary namespace, so the aliases compile when this header comes first. Define
// DMK_NO_NAMESPACE_ALIASES before the first DetourModKit include to suppress the `dmk` and `DMK` aliases ([B-78]).
namespace DetourModKit
{
} // namespace DetourModKit
#if !defined(DMK_NO_NAMESPACE_ALIASES)
namespace dmk = DetourModKit;
namespace DMK = DetourModKit;
#endif

// DMK_ARCH_X64 is the numeric architecture flag. CMake configure rejects a non-Windows target, and the installed
// package rejects a consumer whose target system, pointer size, architecture, or STL differs from the archive.
#if (defined(_M_X64) || defined(__x86_64__)) && !defined(_M_ARM64EC)
#define DMK_ARCH_X64 1
#else
#define DMK_ARCH_X64 0
#endif
#if !DMK_ARCH_X64 || !defined(_WIN32)
#error "DetourModKit supports native x86-64 Windows only. ARM64EC and all other targets are unsupported."
#endif

/**
 * @brief Emits the bitwise `| & ^ ~` and compound `|= &= ^=` operators for a scoped flag enum.
 * @details Invoke it inside the namespace that owns the enum, with the unqualified enum name. Argument-dependent lookup
 *          then finds the operators. A qualified invocation after the closing brace emits them at global scope. Put no
 *          semicolon after the invocation, because `-Wextra-semi` warns on a stray `;` at namespace scope.
 */
#define DMK_FLAG_ENUM(EnumType)                                                                                        \
    constexpr EnumType operator|(EnumType lhs, EnumType rhs) noexcept                                                  \
    {                                                                                                                  \
        return static_cast<EnumType>(                                                                                  \
            static_cast<std::underlying_type_t<EnumType>>(lhs) | static_cast<std::underlying_type_t<EnumType>>(rhs)    \
        );                                                                                                             \
    }                                                                                                                  \
    constexpr EnumType operator&(EnumType lhs, EnumType rhs) noexcept                                                  \
    {                                                                                                                  \
        return static_cast<EnumType>(                                                                                  \
            static_cast<std::underlying_type_t<EnumType>>(lhs) & static_cast<std::underlying_type_t<EnumType>>(rhs)    \
        );                                                                                                             \
    }                                                                                                                  \
    constexpr EnumType operator^(EnumType lhs, EnumType rhs) noexcept                                                  \
    {                                                                                                                  \
        return static_cast<EnumType>(                                                                                  \
            static_cast<std::underlying_type_t<EnumType>>(lhs) ^ static_cast<std::underlying_type_t<EnumType>>(rhs)    \
        );                                                                                                             \
    }                                                                                                                  \
    constexpr EnumType operator~(EnumType value) noexcept                                                              \
    {                                                                                                                  \
        return static_cast<EnumType>(~static_cast<std::underlying_type_t<EnumType>>(value));                           \
    }                                                                                                                  \
    constexpr EnumType &operator|=(EnumType &lhs, EnumType rhs) noexcept                                               \
    {                                                                                                                  \
        return lhs = lhs | rhs;                                                                                        \
    }                                                                                                                  \
    constexpr EnumType &operator&=(EnumType &lhs, EnumType rhs) noexcept                                               \
    {                                                                                                                  \
        return lhs = lhs & rhs;                                                                                        \
    }                                                                                                                  \
    constexpr EnumType &operator^=(EnumType &lhs, EnumType rhs) noexcept                                               \
    {                                                                                                                  \
        return lhs = lhs ^ rhs;                                                                                        \
    }

// DMK_LIFETIMEBOUND marks a parameter or implicit object that a returned view borrows, so the compiler can warn about
// a dangling view. It is a diagnostic aid, not an ABI feature. GCC has no equivalent, so it expands to nothing there.
#if defined(__clang__)
#define DMK_LIFETIMEBOUND [[clang::lifetimebound]]
#elif defined(_MSC_VER)
#define DMK_LIFETIMEBOUND [[msvc::lifetimebound]]
#else
#define DMK_LIFETIMEBOUND
#endif

#endif // DETOURMODKIT_DEFINES_HPP
