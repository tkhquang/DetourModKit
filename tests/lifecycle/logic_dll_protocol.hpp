#ifndef DETOURMODKIT_TESTS_LIFECYCLE_LOGIC_DLL_PROTOCOL_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_LOGIC_DLL_PROTOCOL_HPP

#include <cstdint>
#include <functional>

/**
 * @file logic_dll_protocol.hpp
 * @brief The callback-only ABI shared by the Logic DLL fixture and the host that owns DetourModKit.
 * @details The fixture models the supported hot-reload topology: the host links DetourModKit and owns every Hook,
 *          binding, and config registration, while the Logic DLL contributes only executable callables. The DLL must
 *          not link the archive, and this header must not require it to. Only a forward declaration of
 *          hook::MidContext is needed because a mid detour never dereferences its context here.
 *
 *          Every entry point is resolved with GetProcAddress rather than an import library: an import would take a
 *          loader reference the host cannot drop, and the whole point of the proofs is to unmap the DLL. The function
 *          types below are therefore the single source of truth for both sides, and the DLL static_asserts its
 *          definitions against them so a signature can never drift between the two translation units.
 */

namespace DetourModKit::hook
{
    struct MidContext;
} // namespace DetourModKit::hook

namespace logic_dll
{
    /// Bare module name; the loader resolves it from the application directory, where both targets are built.
    inline constexpr const char *MODULE_NAME = "logic_callback_dll.dll";

    /**
     * @enum Counter
     * @brief Event tallies the DLL maintains, read one at a time through @ref CounterFn.
     * @details The construction and destruction counters cover the DLL-defined target copied into erased storage. The
     *          scenarios destroy their host-local copies before reading the difference, so any remainder identifies
     *          callback code still owned by the library or a consumer-held guard.
     */
    enum class Counter : int
    {
        CallableConstructed = 0,
        CallableDestroyed,
        PressInvoked,
        HoldInvoked,
        SetterInvoked,
        ReloadInvoked,
        MidInvoked,
        InlineInvoked,
        Count
    };

    /**
     * @enum Channel
     * @brief Callback channels a host can park, holding DLL code live inside DetourModKit across a drain attempt.
     */
    enum class Channel : int
    {
        Press = 0,
        Hold,
        Setter,
        Reload,
        Mid,
        Inline,
        Count
    };

    /// Upper bound on a parked body's wait, so a proof whose release never arrives exits instead of wedging.
    inline constexpr std::uint32_t PARK_WAIT_LIMIT_MS = 30000;

    /// Zeroes every tally, disarms every park, and provisions the park events. Call once before anything else.
    using ResetFn = void (*)() noexcept;

    /// Reads one @ref Counter. An out-of-range index reads zero.
    using CounterFn = std::uint64_t (*)(int counter) noexcept;

    /// Arms a @ref Channel, so the next body on that channel signals entry and waits for a release.
    using ArmParkFn = void (*)(int channel) noexcept;

    /// Releases a parked @ref Channel and disarms it, so later bodies run straight through.
    using ReleaseParkFn = void (*)(int channel) noexcept;

    /// Blocks until a body has entered the armed @ref Channel, or the timeout expires. Nonzero means parked.
    using WaitParkedFn = int (*)(int channel, std::uint32_t timeout_ms) noexcept;

    /// Assigns a DLL-defined callable whose invoker, copy manager, and destructor all live in the DLL.
    using MakePressCallableFn = void (*)(std::function<void()> *out) noexcept;

    /// Assigns a DLL-defined hold state callable. Same ownership properties as @ref MakePressCallableFn.
    using MakeHoldCallableFn = void (*)(std::function<void(bool)> *out) noexcept;

    /// Assigns a DLL-defined config setter callable. Same ownership properties as @ref MakePressCallableFn.
    using MakeSetterCallableFn = void (*)(std::function<void(int)> *out) noexcept;

    /// Assigns a DLL-defined reload-notification callable. Same ownership properties as @ref MakePressCallableFn.
    using MakeReloadCallableFn = void (*)(std::function<void(bool)> *out) noexcept;

    /// Makes the next callable factory simulate an allocation failure, which the C ABI must contain.
    using FailNextCallableFactoryFn = void (*)() noexcept;

    /// Signature of the hookable target the inline detour replaces.
    using TargetFn = int (*)(int base, int modifier);

    /**
     * @brief What the inline detour returns when it was never handed a trampoline.
     * @details Deliberately not a value the target could produce. An inline detour that recomputed the target's result
     *          instead of chaining would be indistinguishable from one that chained, so the unchained path has to be
     *          observable or the host's chain assertion proves nothing.
     */
    inline constexpr int UNCHAINED_RESULT = -0x5EED;

    /// Hands the inline detour the trampoline it should chain to. Must be set before the hook is armed.
    using SetInlineOriginalFn = void (*)(TargetFn original) noexcept;

    /// The DLL-defined mid detour, passed to hook::mid_at. It tallies and parks; it never reads the context.
    using MidDetourFn = void (*)(DetourModKit::hook::MidContext &context) noexcept;

    /// The DLL-defined inline detour, passed to hook::inline_at. It tallies, parks, then chains to the original.
    using InlineDetourFn = int (*)(int base, int modifier) noexcept;

    inline constexpr const char *RESET_SYMBOL = "dmk_logic_reset";
    inline constexpr const char *COUNTER_SYMBOL = "dmk_logic_counter";
    inline constexpr const char *ARM_PARK_SYMBOL = "dmk_logic_arm_park";
    inline constexpr const char *RELEASE_PARK_SYMBOL = "dmk_logic_release_park";
    inline constexpr const char *WAIT_PARKED_SYMBOL = "dmk_logic_wait_parked";
    inline constexpr const char *MAKE_PRESS_CALLABLE_SYMBOL = "dmk_logic_make_press_callable";
    inline constexpr const char *MAKE_HOLD_CALLABLE_SYMBOL = "dmk_logic_make_hold_callable";
    inline constexpr const char *MAKE_SETTER_CALLABLE_SYMBOL = "dmk_logic_make_setter_callable";
    inline constexpr const char *MAKE_RELOAD_CALLABLE_SYMBOL = "dmk_logic_make_reload_callable";
    inline constexpr const char *FAIL_NEXT_CALLABLE_FACTORY_SYMBOL = "dmk_logic_fail_next_callable_factory";
    inline constexpr const char *SET_INLINE_ORIGINAL_SYMBOL = "dmk_logic_set_inline_original";
    inline constexpr const char *MID_DETOUR_SYMBOL = "dmk_logic_mid_detour";
    inline constexpr const char *INLINE_DETOUR_SYMBOL = "dmk_logic_inline_detour";

    /**
     * @brief Exported data whose address is the unmap oracle.
     * @details The host resolves it before unloading and keeps the raw address. GetModuleHandleExW with
     *          FROM_ADDRESS reports whether any module still owns that address, which is the only claim that
     *          distinguishes a real unmap from a FreeLibrary that merely dropped one reference.
     */
    inline constexpr const char *MARKER_SYMBOL = "dmk_logic_marker";
} // namespace logic_dll

#endif // DETOURMODKIT_TESTS_LIFECYCLE_LOGIC_DLL_PROTOCOL_HPP
