#ifndef DETOURMODKIT_DEFINES_HPP
#define DETOURMODKIT_DEFINES_HPP

/**
 * @file defines.hpp
 * @brief Single home for every cross-compiler portability primitive in DetourModKit.
 * @details Routes all toolchain- and architecture-conditional spellings through this one header, so no other public
 *          header carries its own `#if defined(_MSC_VER)` ladder. It provides the architecture gate, the flag-enum
 *          operator generator, the lifetime-bound annotation, the library-visibility marker, and the short
 *          `dmk` / `DMK` namespace aliases (suppressed by defining `DMK_NO_NAMESPACE_ALIASES`).
 *
 *          Runtime SIMD tier selection is deliberately NOT here: it is chosen at run time inside the scan engine, and
 *          the per-function `target` attributes live beside that engine.
 */

#include <type_traits>

// Establish the primary namespace so the short aliases below are well-formed even when this header is included first.
// `dmk::Foo` and `DMK::Foo` name the same entity as `DetourModKit::Foo`. The aliases are convenience, not contract:
// defining DMK_NO_NAMESPACE_ALIASES before the first DetourModKit include suppresses both ([B-78]), and the primary
// namespace is always established, so no capability is lost.
namespace DetourModKit
{
} // namespace DetourModKit
#if !defined(DMK_NO_NAMESPACE_ALIASES)
namespace dmk = DetourModKit;
namespace DMK = DetourModKit;
#endif

// DetourModKit targets native x86-64 Windows. Its scan and hook engines depend on that instruction set and platform.
// DMK_ARCH_X64 provides a numeric architecture flag. The #error gives consumers one direct platform diagnostic.
// CMake configure and the installed package enforce the same target contract.
#if (defined(_M_X64) || defined(__x86_64__)) && !defined(_M_ARM64EC)
#define DMK_ARCH_X64 1
#else
#define DMK_ARCH_X64 0
#endif
#if !DMK_ARCH_X64 || !defined(_WIN32)
#error "DetourModKit supports native x86-64 Windows only. ARM64EC and all other targets are unsupported."
#endif

// Flag-enum operator generator
/**
 * @brief Emits the bitwise `| & ^ ~` and compound `|= &= ^=` operators for a scoped flag enum.
 * @details A scoped flag enum needs explicit operators before `a | b` compiles. This macro defines them in terms of
 *          the enum's own underlying type. Invoke it INSIDE the namespace that owns the enum and pass the UNQUALIFIED
 *          enum name, so argument-dependent lookup finds the operators. Invoking it after the closing brace with a
 *          qualified name wrongly emits the operators at global scope.
 *
 *          Invoke WITHOUT a trailing semicolon. The macro already expands to a sequence of complete function
 *          definitions, and a stray `;` at namespace scope is an extra-declaration that `-Wpedantic` flags.
 */
#define DMK_FLAG_ENUM(EnumType)                                                                                        \
    constexpr EnumType operator|(EnumType lhs, EnumType rhs) noexcept                                                  \
    {                                                                                                                  \
        return static_cast<EnumType>(static_cast<std::underlying_type_t<EnumType>>(lhs) |                              \
                                     static_cast<std::underlying_type_t<EnumType>>(rhs));                              \
    }                                                                                                                  \
    constexpr EnumType operator&(EnumType lhs, EnumType rhs) noexcept                                                  \
    {                                                                                                                  \
        return static_cast<EnumType>(static_cast<std::underlying_type_t<EnumType>>(lhs) &                              \
                                     static_cast<std::underlying_type_t<EnumType>>(rhs));                              \
    }                                                                                                                  \
    constexpr EnumType operator^(EnumType lhs, EnumType rhs) noexcept                                                  \
    {                                                                                                                  \
        return static_cast<EnumType>(static_cast<std::underlying_type_t<EnumType>>(lhs) ^                              \
                                     static_cast<std::underlying_type_t<EnumType>>(rhs));                              \
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

// Lifetime-bound annotation
// Marks a reference/view/span parameter (or the implicit object of a view-returning method) as bound to the caller's
// temporary, so the compiler can warn when that temporary dies before the returned view does. It is a diagnostic aid,
// not an ABI feature: Clang and MSVC implement it, GCC has no equivalent attribute (the MinGW build relies instead on
// the structural owning/borrowed split plus `-Wdangling-reference`), so it must expand to nothing there.
#if defined(__clang__)
#define DMK_LIFETIMEBOUND [[clang::lifetimebound]]
#elif defined(_MSC_VER)
#define DMK_LIFETIMEBOUND [[msvc::lifetimebound]]
#else
#define DMK_LIFETIMEBOUND
#endif

// Library visibility marker
// DetourModKit ships as a static archive: the consumer performs the final link, so DMK_API expands to nothing. It is
// the single attachment point for visibility control if a shared-library build is ever introduced.
#define DMK_API

#endif // DETOURMODKIT_DEFINES_HPP
