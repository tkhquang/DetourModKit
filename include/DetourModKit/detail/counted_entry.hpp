#ifndef DETOURMODKIT_DETAIL_COUNTED_ENTRY_HPP
#define DETOURMODKIT_DETAIL_COUNTED_ENTRY_HPP

/**
 * @file counted_entry.hpp
 * @brief The counted thunk that @ref DetourModKit::hook::inline_at installs in front of a typed detour (`[B-106]`).
 * @details The thunk counts every call into and out of the detour, so a retirement can prove the detour idle before
 *          the image unmaps. The install decodes each instantiated thunk and refuses a shape that the proof cannot
 *          cover. The counts therefore use compiler intrinsics and a C array, so they need no helper call at any
 *          optimization level.
 */

#include "DetourModKit/defines.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace DetourModKit::hook::detail
{
#ifdef _MSC_VER
#pragma warning(push)
// The stripe carries its cache-line alignment, so the padding that C4324 reports is intended.
#pragma warning(disable : 4324)
#endif

    /// The calls that entered and left a counted detour on the threads of one stripe.
    struct alignas(64) CountedStripe
    {
        std::uint64_t enters;
        std::uint64_t exits;
    };

#ifdef _MSC_VER
#pragma warning(pop)
#endif

    /// The stripe count. The thread id in the TEB selects a stripe, so concurrent callers rarely share a cache line.
    inline constexpr std::size_t COUNTED_STRIPES = 16;
    static_assert((COUNTED_STRIPES & (COUNTED_STRIPES - 1)) == 0, "the stripe mask needs a power of two");

    /**
     * @brief The counters of one counted detour. Constant initialization fills it, and it is trivially destructible
     *        (`[B-47]`), so it stays valid during static destruction.
     */
    struct CountedBlock
    {
        // A C array, because std::array::operator[] is an out-of-line call in an unoptimized consumer build.
        CountedStripe stripes[COUNTED_STRIPES];
    };

    static_assert(std::is_trivially_destructible_v<CountedBlock>, "the counters must outlive static destruction");

    /// The thunk and its counters, as @ref inline_at hands them to the install.
    struct CountedInstall
    {
        void *entry = nullptr;
        CountedBlock *block = nullptr;
    };

    /**
     * @brief True when the thunk forwards a parameter or result of type @p T unchanged.
     * @details @p T is a reference or a trivially copyable object, and it is not @p Frame. The frame passes only by
     *          value in the first position, so a frame anywhere else reads a game argument as a stack slot.
     */
    template <class T, class Frame>
    inline constexpr bool counted_value_v =
        (std::is_reference_v<T> || std::is_trivially_copyable_v<T>) && !std::is_same_v<std::remove_cvref_t<T>, Frame>;

#if defined(_MSC_VER)
#define DMK_DETAIL_COUNTED_THUNK __declspec(noinline) __declspec(safebuffers) __declspec(no_sanitize_address)
#define DMK_DETAIL_COUNTED_INCREMENT(counter)                                                                          \
    _InterlockedIncrement64(reinterpret_cast<volatile long long *>(&(counter)))
#define DMK_DETAIL_COUNTED_THREAD_ID(name) const std::uint64_t name = __readgsqword(0x48)
#define DMK_DETAIL_COUNTED_RETURN_SLOT() static_cast<void **>(_AddressOfReturnAddress())
#else
// Clang has no noipa, and it changes no signature of a function whose address escapes. A stack protector check is a
// conditional branch, which the install decode refuses, so the thunk opts out as safebuffers does under MSVC.
#if defined(__clang__)
#define DMK_DETAIL_COUNTED_THUNK [[gnu::noinline, gnu::no_sanitize_address, gnu::no_stack_protector]]
#else
#define DMK_DETAIL_COUNTED_THUNK [[gnu::noipa, gnu::no_sanitize_address, gnu::no_stack_protector]]
#endif
#define DMK_DETAIL_COUNTED_INCREMENT(counter) __atomic_add_fetch(&(counter), 1, __ATOMIC_SEQ_CST)
#define DMK_DETAIL_COUNTED_THREAD_ID(name)                                                                             \
    std::uint64_t name;                                                                                                \
    __asm__("movq %%gs:0x48, %0" : "=r"(name))
#define DMK_DETAIL_COUNTED_RETURN_SLOT() (static_cast<void **>(__builtin_dwarf_cfa()) - 1)
#endif

    /**
     * @brief The counted thunk and counters of one detour.
     * @tparam Detour The detour. The thunk calls it through @ref detour, a volatile read, so the compiler cannot
     *         inline it and the call stays one instruction.
     * @tparam Frame The frame type that the detour takes first, or void for a detour without one.
     * @details The relay slot jumps to @ref entry, so the thunk runs with the stack of the game caller. Its
     *          parameters and stack arguments therefore match the hooked function. Each enter and exit is a seq_cst
     *          locked increment (`[B-43]`).
     */
    template <auto Detour, class Frame, class Ret, class... Args> struct CountedEntry
    {
        /// The counters that the drain proof reads.
        static constinit inline CountedBlock block{};
        /// The detour behind a volatile read. Constant initialization fills it.
        static constinit inline decltype(Detour) volatile detour = Detour;

        /// The thunk. Only the relay slot of the hook reaches it.
        DMK_DETAIL_COUNTED_THUNK static Ret entry(Args... args) noexcept
        {
            DMK_DETAIL_COUNTED_THREAD_ID(thread_id);
            CountedStripe &stripe = block.stripes[(thread_id >> 2) & (COUNTED_STRIPES - 1)];
            DMK_DETAIL_COUNTED_INCREMENT(stripe.enters);
            if constexpr (std::is_void_v<Ret>)
            {
                if constexpr (std::is_void_v<Frame>)
                {
                    detour(static_cast<Args &&>(args)...);
                }
                else
                {
                    detour(Frame{DMK_DETAIL_COUNTED_RETURN_SLOT()}, static_cast<Args &&>(args)...);
                }
                DMK_DETAIL_COUNTED_INCREMENT(stripe.exits);
            }
            else
            {
                if constexpr (std::is_void_v<Frame>)
                {
                    Ret value = detour(static_cast<Args &&>(args)...);
                    DMK_DETAIL_COUNTED_INCREMENT(stripe.exits);
                    return value;
                }
                else
                {
                    Ret value = detour(Frame{DMK_DETAIL_COUNTED_RETURN_SLOT()}, static_cast<Args &&>(args)...);
                    DMK_DETAIL_COUNTED_INCREMENT(stripe.exits);
                    return value;
                }
            }
        }
    };

#undef DMK_DETAIL_COUNTED_RETURN_SLOT
#undef DMK_DETAIL_COUNTED_THREAD_ID
#undef DMK_DETAIL_COUNTED_INCREMENT
#undef DMK_DETAIL_COUNTED_THUNK

    /**
     * @brief Classifies a detour type for the counted thunk.
     * @details The primary template rejects every type that is not a non-variadic noexcept function pointer.
     */
    template <class Fn, class Frame> struct CountedSignature
    {
        static constexpr bool valid = false;
    };

    /// A detour without a frame parameter.
    template <class Ret, class... Args, class Frame> struct CountedSignature<Ret (*)(Args...) noexcept, Frame>
    {
        static constexpr bool valid =
            (std::is_void_v<Ret> || counted_value_v<Ret, Frame>) && (counted_value_v<Args, Frame> && ...);

        template <auto Detour> using entry = CountedEntry<Detour, void, Ret, Args...>;
    };

    /// A detour that takes @p Frame first.
    template <class Ret, class... Args, class Frame> struct CountedSignature<Ret (*)(Frame, Args...) noexcept, Frame>
    {
        static constexpr bool valid =
            (std::is_void_v<Ret> || counted_value_v<Ret, Frame>) && (counted_value_v<Args, Frame> && ...);

        template <auto Detour> using entry = CountedEntry<Detour, Frame, Ret, Args...>;
    };
} // namespace DetourModKit::hook::detail

#endif // DETOURMODKIT_DETAIL_COUNTED_ENTRY_HPP
