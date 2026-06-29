#ifndef DETOURMODKIT_DEFINES_HPP
#define DETOURMODKIT_DEFINES_HPP

/**
 * @file defines.hpp
 * @brief Single home for every cross-compiler portability primitive in DetourModKit.
 * @details The v4 surface routes ALL toolchain- and architecture-conditional spellings through this one header so
 *          that no other public header has to carry its own `#if defined(_MSC_VER)` ladder. It provides the
 *          architecture gate, the force-inline attribute, the flag-enum operator generator, the lifetime-bound
 *          annotation, the library-visibility marker, and the short `dmk` namespace alias. Keeping them together means
 *          a future toolchain port touches exactly one file, and every other header reads as plain C++23.
 *
 *          Runtime SIMD tier selection (SSE2 / AVX2 / opt-in AVX-512) is deliberately NOT here: it is chosen at run
 *          time through a CPUID + XGETBV probe inside the scan engine, and the matching per-function `target`
 *          attributes live beside that engine because they only decorate its tiered kernels. This header carries the
 *          portability vocabulary the public type surface needs; the scan engine keeps its ISA-specific machinery
 *          local to itself.
 */

#include <type_traits>

// Establish the primary namespace so the short alias below is well-formed even when this header is included first,
// then publish `dmk` as the canonical shorthand. Every public type lives in DetourModKit; `dmk::Foo` is the exact
// same entity reached through a shorter name, so consumer code can spell it either way without an adapter.
namespace DetourModKit
{
} // namespace DetourModKit
namespace dmk = DetourModKit;

// Target architecture gate
// DetourModKit manipulates raw process memory and 64-bit code on Win64 game targets; an Address is exactly a machine
// pointer and the scan/hook engines assume the x86-64 register file and instruction encodings. Encode the target as a
// 1/0 macro so it can drive both `#if` ladders and the static_assert that fails the build early on an unsupported
// architecture rather than at some later, more confusing miscompile.
#if defined(_M_X64) || defined(__x86_64__)
#define DMK_ARCH_X64 1
#else
#define DMK_ARCH_X64 0
#endif

static_assert(DMK_ARCH_X64 == 1, "DetourModKit targets x86-64 (Win64) only; no 32-bit or non-x86 build is supported.");

// Force inline
// `inline` alone is only a linkage/ODR hint and lets the optimizer decline to inline a hot accessor. The force-inline
// spelling is the strongest portable request to actually fold the body into the caller, which matters on the
// per-access fast paths (address arithmetic, register accessors) where a real call would dwarf the work. It stays a
// request, not a guarantee: a compiler may still refuse (e.g. a recursive or address-taken function).
#if defined(_MSC_VER)
#define DMK_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_FORCE_INLINE inline __attribute__((always_inline))
#else
#define DMK_FORCE_INLINE inline
#endif

// Flag-enum operator generator
/**
 * @brief Emits the bitwise `| & ^ ~` and compound `|= &= ^=` operators for a scoped flag enum.
 * @details A C++ `enum class` deliberately suppresses implicit integral conversions, so a bitmask enum needs explicit
 *          operators before `a | b` compiles. This macro defines them in terms of the enum's own underlying type, so
 *          the result never escapes the enum's value domain. Invoke it INSIDE the namespace that owns the enum and
 *          pass the UNQUALIFIED enum name: the operators are then defined in that same namespace, where
 *          argument-dependent lookup finds them, and two flag enums that happen to share an underlying type never
 *          collide. Invoking it after the closing brace with a qualified name (`DMK_FLAG_ENUM(DetourModKit::Prot)`)
 *          cannot reopen the namespace and would wrongly emit the operators at global scope.
 *
 *          Invoke WITHOUT a trailing semicolon -- the macro already expands to a sequence of complete function
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
// DetourModKit ships as a static archive: the consumer performs the final link of the mod DLL/EXE, so no
// dllexport/dllimport decoration is required and DMK_API expands to nothing. It exists as the single, already-applied
// attachment point should a shared-library build ever be introduced, so adding visibility control would not mean
// re-touching every declaration.
#define DMK_API

#endif // DETOURMODKIT_DEFINES_HPP
