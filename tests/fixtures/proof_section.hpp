#ifndef DETOURMODKIT_TESTS_FIXTURES_PROOF_SECTION_HPP
#define DETOURMODKIT_TESTS_FIXTURES_PROOF_SECTION_HPP

/**
 * @file proof_section.hpp
 * @brief Defines the noinline markers for in-image test functions and a call helper that always reaches the entry
 *        of a hook target.
 * @details docs/design/testing.md owns the `.proof` rule under "In-image hook targets live in their own section".
 */

#include <cstdint>

/**
 * @brief Marks a noinline hook target and places it in `.proof`.
 * @details The per-function form also places a template instantiation, which MSVC `#pragma code_seg` does not.
 */
#if defined(_MSC_VER)
#define DMK_PROOF_TARGET __declspec(noinline) __declspec(code_seg(".proof"))
#else
#define DMK_PROOF_TARGET __attribute__((noinline, section(".proof")))
#endif

/** @brief Marks a noinline function that no test patches, such as a detour. Hook targets use DMK_PROOF_TARGET. */
#if defined(_MSC_VER)
#define DMK_TEST_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define DMK_TEST_NOINLINE [[gnu::noinline]]
#else
#define DMK_TEST_NOINLINE
#endif

/**
 * @brief Defines `int NAME(int)` as a `.proof` target whose code differs for each SEED.
 * @details The distinct seed prevents code folding. The volatile loop keeps the body long enough for either patch
 *          form. Unsigned arithmetic avoids overflow.
 */
#define DMK_PROOF_SEEDED_TARGET(NAME, SEED)                                                                            \
    DMK_PROOF_TARGET int NAME(int value)                                                                               \
    {                                                                                                                  \
        constexpr std::uint32_t SEED_VALUE = static_cast<std::uint32_t>(SEED);                                         \
        volatile std::uint32_t accumulator = static_cast<std::uint32_t>(value) * SEED_VALUE;                           \
        for (std::uint32_t i = 0; i < 8; ++i)                                                                          \
        {                                                                                                              \
            accumulator = accumulator + ((accumulator >> 3) ^ (i * SEED_VALUE));                                       \
            accumulator = accumulator ^ (accumulator << 5);                                                            \
        }                                                                                                              \
        return static_cast<int>(accumulator & 0xFFFFu) + (SEED);                                                       \
    }

namespace dmk_test
{
    /** @brief Reaches the patched entry through volatile indirection even when the optimizer sees the callee. */
    template <class Fn, class... Args> auto call_unfolded(Fn *fn, Args... args)
    {
        Fn *const volatile indirect = fn;
        return indirect(args...);
    }
} // namespace dmk_test

#endif // DETOURMODKIT_TESTS_FIXTURES_PROOF_SECTION_HPP
