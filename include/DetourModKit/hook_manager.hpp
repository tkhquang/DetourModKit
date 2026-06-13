#ifndef DETOURMODKIT_HOOK_MANAGER_HPP
#define DETOURMODKIT_HOOK_MANAGER_HPP

#include "DetourModKit/format.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/scanner.hpp"
#include "DetourModKit/srw_shared_mutex.hpp"

#include "safetyhook.hpp"

#include <atomic>
#include <concepts>
#include <cstdint>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Transparent hash functor for heterogeneous lookup in string-keyed maps.
         * @details Allows std::string_view lookups without constructing a temporary std::string.
         */
        struct TransparentStringHash
        {
            using is_transparent = void;
            size_t operator()(std::string_view sv) const noexcept { return std::hash<std::string_view>{}(sv); }
        };
    } // namespace detail

    /**
     * @enum HookType
     * @brief Enumeration of supported hook types, corresponding to SafetyHook capabilities.
     */
    enum class HookType
    {
        Inline,
        Mid,
        Vmt
    };

    /**
     * @enum HookStatus
     * @brief Represents the current operational status of a managed hook.
     */
    enum class HookStatus
    {
        Active,
        Disabled,
        Enabling,
        Disabling
    };

    /**
     * @enum InlineProloguePolicy
     * @brief Escalation policy for the inline/mid hook prologue pre-flight.
     * @details Controls what happens when the target's first opcode is a leading E8 (call rel32) or a breakpoint byte
     *          (0xCC int3 / 0xCD int n) at create time. A leading call means the inline hook's 5-byte E9 patch would
     *          steal a relative call whose displacement was computed from the original site, so the relocated
     *          trampoline copy can dispatch the call to the wrong absolute target; a leading int3 means the slot is
     *          already a breakpoint -- a foreign hook's stub, a patched byte, or alignment padding -- not a real
     *          function body. @ref Warn logs and installs anyway (the default, preserving historical behaviour); @ref
     *          Fail refuses the create with @ref HookError::TargetPrologueUnsafe.
     */
    enum class InlineProloguePolicy
    {
        Warn,
        Fail
    };

    /**
     * @enum HookError
     * @brief Error codes for hook creation/operation failures.
     */
    enum class HookError
    {
        AllocatorNotAvailable,
        InvalidTargetAddress,
        InvalidDetourFunction,
        InvalidTrampolinePointer,
        HookAlreadyExists,
        HookNotFound,
        ShutdownInProgress,
        SafetyHookError,
        EnableFailed,
        DisableFailed,
        InvalidHookState,
        InvalidObject,
        VmtHookNotFound,
        MethodAlreadyHooked,
        MethodNotFound,
        TargetAlreadyHookedInProcess,
        ReentrantCallRejected,
        TargetPrologueUnsafe,
        UnknownError
    };

    /**
     * @struct HookConfig
     * @brief Configuration options used during the creation of a new hook.
     */
    struct HookConfig
    {
        bool auto_enable = true;

        /**
         * @brief Refuses hooks when the target already appears hooked.
         * @details Applies to inline and mid hooks. The pre-flight first checks this HookManager's registry for an
         *          exact same-address hook, then falls back to a foreign JMP prologue heuristic. With the default
         *          (false), a warning is logged and bulk teardown unwinds managed layers newest-first.
         */
        bool fail_if_already_hooked = false;

        /**
         * @brief Escalation policy when the target prologue leads with a call (E8) or a breakpoint (0xCC/0xCD) byte.
         * @details A leading 0xE8 call rel32 or a 0xCC/0xCD breakpoint at the hook site is the risk this surfaces:
         *          hooking a prologue that is itself a relative call steals a displacement that was relative to the
         *          original address (the relocated trampoline copy can then call the wrong absolute target), and
         *          hooking an int3 byte means the entry is already a breakpoint stub (a foreign hook or a patched /
         *          padding byte), not a real function body. The pre-flight decodes the first byte under a fault guard
         *          and, on a match, either logs a warning and installs anyway (@ref InlineProloguePolicy::Warn, the
         *          default, preserving current behaviour) or refuses with @ref HookError::TargetPrologueUnsafe (@ref
         *          InlineProloguePolicy::Fail). Applies to inline and mid hooks; both patch the same prologue. A rare
         *          legitimate function whose true first instruction is a call thunk will warn (harmless) or, under
         *          Fail, be refused -- opt into Fail only for targets known to be ordinary function bodies.
         */
        InlineProloguePolicy prologue_policy = InlineProloguePolicy::Warn;
    };

    /**
     * @struct VmtHookConfig
     * @brief Configuration options used during VMT hook creation and apply, symmetric with @ref HookConfig.
     * @details Mirrors @ref HookConfig for VMT hooks so the inline and VMT code paths expose the same operational
     *          surface. The defaults are chosen to preserve the historical single-argument API's behavior exactly
     *          (no pre-flight checks; pre-existing failures such as a null object, a duplicate name, shutdown in
     *          progress, or a SafetyHook error still apply), so existing call sites that build a default config
     *          compile and run unchanged.
     */
    struct VmtHookConfig
    {
        /**
         * @brief When true, refuse to clone an object whose vptr already points at a VMT cloned by this HookManager.
         * @details SafetyHook::VmtHook::create replaces the object's vptr with a pointer into a freshly-allocated
         *          cloned vtable. If a second call later clones the same object, the second create reads the first
         *          clone as if it were the original vtable: the first mod's hooked methods are now baked into the
         *          second mod's "original" and a third call layered on top of the second sees a third level of
         *          redirection. This is the silent "double hook" failure mode the inline hook's
         *          @ref HookConfig::fail_if_already_hooked guards against; VMT cloning is the same shape of risk and
         *          gets the same knob. Default false preserves the legacy permissive behavior.
         */
        bool fail_if_already_hooked = false;

        /**
         * @brief When true, pre-flight-decode the first byte of the original vtable slot and refuse to clone when
         *        the byte is an int3/int padding breakpoint or a same-module jump stub.
         * @details A VMT slot whose first byte is 0xCC is an alignment pad or permanent breakpoint, not a real
         *          function. Replacing it and dispatching through it yields __debugbreak under the consumer's
         *          debugger and an instant crash in shipping builds. A VMT slot whose first instruction is `jmp
         *          rel8/rel32` to a target inside the same module is a jump stub (e.g. an incremental-link ILT
         *          entry), not a function body; MSVC adjustor thunks for multiple-inheritance vtables start with the
         *          this-adjust instruction, so they pass. The check is intentionally conservative: real functions
         *          (any other first byte, or a tail-call `mov reg,reg; jmp <out-of-module>`) pass. Known false
         *          positive: consumer binaries built with /INCREMENTAL route every function through an ILT jump
         *          stub, which this check rejects. The default is false to preserve the historical no-pre-flight
         *          behavior; opt in for the safety net on mods that exclusively target well-formed C++ vtables.
         */
        bool fail_on_non_function_pointer = false;
    };

    /**
     * @class Hook
     * @brief Abstract base class for managed hooks.
     * @details Defines a common interface for interacting with different types of hooks managed by the HookManager.
     *          Implements the Template Method pattern for enable/disable state management.
     */
    class Hook
    {
    public:
        virtual ~Hook() noexcept = default;

        [[nodiscard]] const std::string &get_name() const noexcept { return m_name; }
        [[nodiscard]] HookType get_type() const noexcept { return m_type; }
        [[nodiscard]] uintptr_t get_target_address() const noexcept { return m_target_address; }
        [[nodiscard]] HookStatus get_status() const noexcept { return m_status.load(std::memory_order_acquire); }

        /**
         * @brief Enables the hook.
         * @return Success if the hook was enabled or already active. On failure, the HookError indicates the reason
         *         (SafetyHookError, EnableFailed, InvalidHookState).
         * @note Uses atomic CAS for lock-free status transitions. Thread-safe without requiring external
         *       synchronization. Uses an intermediate Enabling state to prevent other threads from observing a
         *       speculative terminal state while the SafetyHook enable call is in progress.
         */
        [[nodiscard]] std::expected<void, HookError> enable()
        {
            if (!is_impl_valid())
                return std::unexpected(HookError::SafetyHookError);

            HookStatus expected = HookStatus::Disabled;
            if (!m_status.compare_exchange_strong(expected, HookStatus::Enabling, std::memory_order_acq_rel))
            {
                if (expected == HookStatus::Active)
                    return {};
                return std::unexpected(HookError::InvalidHookState);
            }

            if (do_enable())
            {
                m_status.store(HookStatus::Active, std::memory_order_release);
                return {};
            }

            m_status.store(HookStatus::Disabled, std::memory_order_release);
            return std::unexpected(HookError::EnableFailed);
        }

        /**
         * @brief Disables the hook.
         * @return Success if the hook was disabled or already disabled. On failure, the HookError indicates the reason
         *         (SafetyHookError, DisableFailed, InvalidHookState).
         * @note Uses atomic CAS for lock-free status transitions. Thread-safe without requiring external
         *       synchronization. Uses an intermediate Disabling state to prevent other threads from observing a
         *       speculative terminal state while the SafetyHook disable call is in progress.
         */
        [[nodiscard]] std::expected<void, HookError> disable()
        {
            if (!is_impl_valid())
                return std::unexpected(HookError::SafetyHookError);

            HookStatus expected = HookStatus::Active;
            if (!m_status.compare_exchange_strong(expected, HookStatus::Disabling, std::memory_order_acq_rel))
            {
                if (expected == HookStatus::Disabled)
                    return {};
                return std::unexpected(HookError::InvalidHookState);
            }

            if (do_disable())
            {
                m_status.store(HookStatus::Disabled, std::memory_order_release);
                return {};
            }

            m_status.store(HookStatus::Active, std::memory_order_release);
            return std::unexpected(HookError::DisableFailed);
        }

        [[nodiscard]] bool is_enabled() const noexcept
        {
            return m_status.load(std::memory_order_acquire) == HookStatus::Active;
        }

        [[nodiscard]] static constexpr std::string_view status_to_string(HookStatus status) noexcept
        {
            switch (status)
            {
            case HookStatus::Active:
                return "Active";
            case HookStatus::Disabled:
                return "Disabled";
            case HookStatus::Enabling:
                return "Enabling";
            case HookStatus::Disabling:
                return "Disabling";
            default:
                return "Unknown";
            }
        }

        [[nodiscard]] static constexpr std::string_view error_to_string(HookError error) noexcept
        {
            switch (error)
            {
            case HookError::AllocatorNotAvailable:
                return "Allocator not available";
            case HookError::InvalidTargetAddress:
                return "Invalid target address";
            case HookError::InvalidDetourFunction:
                return "Invalid detour function";
            case HookError::InvalidTrampolinePointer:
                return "Invalid trampoline pointer";
            case HookError::HookAlreadyExists:
                return "Hook already exists";
            case HookError::HookNotFound:
                return "Hook not found";
            case HookError::ShutdownInProgress:
                return "Shutdown in progress";
            case HookError::SafetyHookError:
                return "SafetyHook error";
            case HookError::EnableFailed:
                return "Hook enable failed";
            case HookError::DisableFailed:
                return "Hook disable failed";
            case HookError::InvalidHookState:
                return "Hook is in a transitional state";
            case HookError::InvalidObject:
                return "Invalid object pointer";
            case HookError::VmtHookNotFound:
                return "VMT hook not found";
            case HookError::MethodAlreadyHooked:
                return "VMT method already hooked";
            case HookError::MethodNotFound:
                return "VMT method hook not found";
            case HookError::TargetAlreadyHookedInProcess:
                return "Target address is already hooked in this process";
            case HookError::ReentrantCallRejected:
                return "Mutator called reentrantly from within a with_* callback";
            case HookError::TargetPrologueUnsafe:
                return "Target prologue leads with a call (E8) or breakpoint (0xCC/0xCD) byte";
            case HookError::UnknownError:
                return "Unknown error";
            default:
                return "Invalid error code";
            }
        }

    protected:
        std::string m_name;
        HookType m_type;
        uintptr_t m_target_address;
        std::atomic<HookStatus> m_status;

        Hook(std::string name, HookType type, uintptr_t target_address, HookStatus initial_status)
            : m_name(std::move(name)), m_type(type), m_target_address(target_address), m_status(initial_status)
        {
        }

        virtual bool is_impl_valid() const noexcept = 0;
        virtual bool do_enable() = 0;
        virtual bool do_disable() = 0;

        Hook(const Hook &) = delete;
        Hook &operator=(const Hook &) = delete;
        Hook(Hook &&) = delete;
        Hook &operator=(Hook &&) = delete;
    };

    namespace detail
    {
        /// Satisfied only by a pointer-to-function type; the valid cast target for InlineHook::get_original.
        template <typename T>
        concept FunctionPointer = std::is_pointer_v<T> && std::is_function_v<std::remove_pointer_t<T>>;
    } // namespace detail

    /**
     * @class InlineHook
     * @brief Represents a managed inline hook, wrapping a SafetyHook::InlineHook object.
     */
    class InlineHook : public Hook
    {
    public:
        InlineHook(std::string name, uintptr_t target_address, safetyhook::InlineHook hook_obj,
                   HookStatus initial_status)
            : Hook(std::move(name), HookType::Inline, target_address, initial_status),
              m_safetyhook_impl(std::move(hook_obj))
        {
        }

        /**
         * @brief Retrieves the trampoline to call the original function.
         * @tparam T The function pointer type of the original function.
         * @return A function pointer of type T to the original function's trampoline.
         */
        template <detail::FunctionPointer T> [[nodiscard]] T get_original() const noexcept
        {
            return m_safetyhook_impl ? m_safetyhook_impl.original<T>() : nullptr;
        }

    protected:
        bool is_impl_valid() const noexcept override { return static_cast<bool>(m_safetyhook_impl); }
        bool do_enable() override
        {
            auto result = m_safetyhook_impl.enable();
            return result.has_value();
        }
        bool do_disable() override
        {
            auto result = m_safetyhook_impl.disable();
            return result.has_value();
        }

    private:
        safetyhook::InlineHook m_safetyhook_impl;
    };

    /**
     * @class MidHook
     * @brief Represents a managed mid-function hook, wrapping a SafetyHook::MidHook object.
     */
    class MidHook : public Hook
    {
    public:
        MidHook(std::string name, uintptr_t target_address, safetyhook::MidHook hook_obj, HookStatus initial_status)
            : Hook(std::move(name), HookType::Mid, target_address, initial_status),
              m_safetyhook_impl(std::move(hook_obj))
        {
        }

        /**
         * @brief Gets the destination function of this mid-hook.
         * @return safetyhook::MidHookFn The function pointer to the detour.
         */
        [[nodiscard]] safetyhook::MidHookFn get_destination() const noexcept
        {
            return m_safetyhook_impl ? m_safetyhook_impl.destination() : nullptr;
        }

    protected:
        bool is_impl_valid() const noexcept override { return static_cast<bool>(m_safetyhook_impl); }
        bool do_enable() override
        {
            auto result = m_safetyhook_impl.enable();
            return result.has_value();
        }
        bool do_disable() override
        {
            auto result = m_safetyhook_impl.disable();
            return result.has_value();
        }

    private:
        safetyhook::MidHook m_safetyhook_impl;
    };

    namespace detail
    {
        /**
         * @class VmtHookEntry
         * @brief Manages a VMT hook for a single object class, wrapping SafetyHook's VmtHook.
         * @details Owns the cloned vtable and tracks individual method hooks by vtable index. VMT hooks operate at the
         *          object level by replacing the vptr with a cloned vtable. Individual methods are hooked by index
         *          within the cloned table. Does not support enable/disable toggling (SafetyHook VmHook limitation).
         *          Internal: held only inside @ref VmtHookMap and not part of the public API.
         */
        class VmtHookEntry
        {
        public:
            /**
             * @brief Constructs an entry that takes ownership of a SafetyHook VMT hook.
             * @param name The registered hook name.
             * @param vmt_hook The VMT hook to own.
             * @param new_vptr_base The vptr value SafetyHook installed on the seeded object, i.e. `&m_new_vmt[1]`.
             *                      Stored so subsequent apply_vmt_hook calls can detect "object is already on this
             *                      clone" without touching the private SafetyHook layout. Zero is reserved for "not
             *                      recorded" and never matches a real vptr.
             */
            VmtHookEntry(std::string name, safetyhook::VmtHook vmt_hook, std::uintptr_t new_vptr_base)
                : m_name(std::move(name)), m_vmt_hook(std::move(vmt_hook)), m_cloned_vptr_base(new_vptr_base)
            {
            }

            /// Returns the registered hook name.
            [[nodiscard]] const std::string &get_name() const noexcept { return m_name; }

            /// Returns the underlying SafetyHook VMT hook.
            [[nodiscard]] safetyhook::VmtHook &vmt_hook() noexcept { return m_vmt_hook; }

            /// Returns the vptr this entry installed on its seed object, or 0 if unknown.
            [[nodiscard]] std::uintptr_t cloned_vptr_base() const noexcept { return m_cloned_vptr_base; }

            /// Returns true if a method at the given vtable index is hooked.
            [[nodiscard]] bool has_method_hook(size_t index) const noexcept
            {
                return m_method_hooks.find(index) != m_method_hooks.end();
            }

            /**
             * @brief Returns the method hook installed at a vtable index.
             * @param index The vtable index to look up.
             * @return Pointer to the method hook, or nullptr if none is installed.
             */
            [[nodiscard]] safetyhook::VmHook *get_method_hook(size_t index)
            {
                auto it = m_method_hooks.find(index);
                return it != m_method_hooks.end() ? &it->second : nullptr;
            }

            /**
             * @brief Installs a method hook at a vtable index.
             * @param index The vtable index being hooked.
             * @param hook The method hook to own.
             */
            void add_method_hook(size_t index, safetyhook::VmHook hook)
            {
                m_method_hooks.emplace(index, std::move(hook));
            }

            /**
             * @brief Removes the method hook at a vtable index.
             * @param index The vtable index to clear.
             * @return true if a hook was removed, false if none was installed.
             */
            [[nodiscard]] bool remove_method_hook(size_t index) { return m_method_hooks.erase(index) > 0; }

            VmtHookEntry(const VmtHookEntry &) = delete;
            VmtHookEntry &operator=(const VmtHookEntry &) = delete;
            VmtHookEntry(VmtHookEntry &&) = default;
            VmtHookEntry &operator=(VmtHookEntry &&) = default;

        private:
            std::string m_name;
            safetyhook::VmtHook m_vmt_hook;
            std::uintptr_t m_cloned_vptr_base{0};
            std::unordered_map<size_t, safetyhook::VmHook> m_method_hooks;
        };

        /**
         * @brief Container type for the inline / mid hook registry, keyed by hook name.
         * @details Centralized once so every site that references this exact instantiation sees identical template
         *          arguments.
         */
        using HookMap = std::unordered_map<std::string, std::unique_ptr<Hook>, TransparentStringHash, std::equal_to<>>;

        /**
         * @brief Container type for the VMT hook registry, keyed by hook name.
         * @details Centralized once so every site that references this exact instantiation sees identical template
         *          arguments.
         */
        using VmtHookMap = std::unordered_map<std::string, VmtHookEntry, TransparentStringHash, std::equal_to<>>;
    } // namespace detail

    /**
     * @class HookManager
     * @brief Manages the lifecycle of all hooks (Inline, Mid, and VMT) using SafetyHook.
     * @details Provides a centralized API for creating, removing, enabling, and disabling hooks. Thread-safe for all
     *          public methods. Uses std::expected for explicit error handling.
     * @note Lock ordering: 1. m_mutator_gate (shared or exclusive) then 2. m_hooks_mutex (shared or exclusive).
     *          Mutators (create_*_hook, enable, disable, remove) acquire shared m_mutator_gate first, then shared or
     *          exclusive m_hooks_mutex. Shutdown and remove_all_hooks acquire exclusive m_mutator_gate first to block
     *          new mutators, then proceed with two-phase cleanup.
     */
    class HookManager
    {
    public:
        /**
         * @brief Provides access to the singleton instance of the HookManager.
         * @return HookManager& Reference to the global HookManager instance.
         */
        static HookManager &get_instance();

        ~HookManager() noexcept;

        /**
         * @brief Explicitly shuts down the HookManager, removing all hooks without logging.
         * @details This method is safe to call during shutdown when Logger may be destroyed. It removes all hooks
         *          without attempting to log, preventing use-after-free. The shutdown flag is reset after hooks are
         *          cleared, allowing subsequent hook creation for hot-reload scenarios. The destructor becomes a no-op
         *          only while the flag is set during the shutdown operation itself.
         */
        void shutdown() noexcept;

        // Non-copyable, non-movable (mutex member)
        HookManager(const HookManager &) = delete;
        HookManager &operator=(const HookManager &) = delete;
        HookManager(HookManager &&) = delete;
        HookManager &operator=(HookManager &&) = delete;

        /**
         * @brief Creates an inline hook at a specific target memory address.
         * @param name A unique, descriptive name for the hook.
         * @param target_address The memory address of the function to hook.
         * @param detour_function Pointer to the detour function.
         * @param original_trampoline Output pointer to receive trampoline address.
         * @param config Optional configuration settings for the hook.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         */
        [[nodiscard]] std::expected<std::string, HookError>
        create_inline_hook(std::string_view name, uintptr_t target_address, void *detour_function,
                           void **original_trampoline, const HookConfig &config = HookConfig());

        /**
         * @brief Creates an inline hook by finding target address via AOB scan.
         * @param name A unique, descriptive name for the hook.
         * @param module_base Base address of the memory module to scan.
         * @param module_size Size of the memory module to scan.
         * @param aob_pattern_str The AOB pattern string.
         * @param aob_offset Offset to add to the found pattern's address.
         * @param detour_function Pointer to the detour function.
         * @param original_trampoline Output pointer to store trampoline address.
         * @param config Optional configuration settings for the hook.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         * @note The AOB scan over [module_base, module_base + module_size) is page-filtered: it walks VirtualQuery
         *       and skips guard, no-access, and non-readable pages, so passing a full SizeOfImage span is safe even
         *       when the image contains a guard or no-access section -- unlike the raw Scanner::find_pattern
         *       overloads, which read the span unconditionally and fault the host on an unreadable byte. A signature
         *       straddling a protection split inside the image is still found, and @p aob_offset is applied to the
         *       located address. For code that lives outside any mapped module (packed payloads unpacked into
         *       anonymous pages), resolve the address with the whole-process Scanner sweeps and call
         *       create_inline_hook with the result instead.
         */
        [[nodiscard]] std::expected<std::string, HookError>
        create_inline_hook_aob(std::string_view name, uintptr_t module_base, size_t module_size,
                               std::string_view aob_pattern_str, ptrdiff_t aob_offset, void *detour_function,
                               void **original_trampoline, const HookConfig &config = HookConfig());

        /**
         * @brief Creates a mid-function hook at a specific target memory address.
         * @param name A unique, descriptive name for the hook.
         * @param target_address The memory address within a function to hook.
         * @param detour_function The function to be called when the mid-hook is executed.
         * @param config Optional configuration settings for the hook.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         */
        [[nodiscard]] std::expected<std::string, HookError> create_mid_hook(std::string_view name,
                                                                            uintptr_t target_address,
                                                                            safetyhook::MidHookFn detour_function,
                                                                            const HookConfig &config = HookConfig());

        /**
         * @brief Creates a mid-function hook by finding target address via AOB scan.
         * @param name A unique, descriptive name for the hook.
         * @param module_base Base address of the memory module to scan.
         * @param module_size Size of the memory module to scan.
         * @param aob_pattern_str The AOB pattern string.
         * @param aob_offset Offset to add to the found pattern's address.
         * @param detour_function The mid-hook detour function.
         * @param config Optional configuration settings for the hook.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         * @note The AOB scan over [module_base, module_base + module_size) is page-filtered: it walks VirtualQuery
         *       and skips guard, no-access, and non-readable pages, so passing a full SizeOfImage span is safe even
         *       when the image contains a guard or no-access section -- unlike the raw Scanner::find_pattern
         *       overloads, which read the span unconditionally and fault the host on an unreadable byte. A signature
         *       straddling a protection split inside the image is still found, and @p aob_offset is applied to the
         *       located address. For code that lives outside any mapped module (packed payloads unpacked into
         *       anonymous pages), resolve the address with the whole-process Scanner sweeps and call
         *       create_mid_hook with the result instead.
         */
        [[nodiscard]] std::expected<std::string, HookError>
        create_mid_hook_aob(std::string_view name, uintptr_t module_base, size_t module_size,
                            std::string_view aob_pattern_str, ptrdiff_t aob_offset,
                            safetyhook::MidHookFn detour_function, const HookConfig &config = HookConfig());

        /**
         * @brief Creates a VMT hook for the given object, cloning its vtable.
         * @param name A unique, descriptive name for the VMT hook.
         * @param object Pointer to the polymorphic object whose vptr will be replaced.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         * @note Setup/control-plane only: clones a vtable, allocates, and takes the HookManager exclusive lock. Call
         *       from init/shutdown or a worker thread, never from a hook or input callback.
         * @warning VMT hooks have no enable/disable: creation swaps the object's vptr to the cloned table and removal
         *          restores it. Removal is a bare vptr write with no thread protection at all -- weaker than inline/mid
         *          teardown, which at least relocates a thread that faults on the patched page via SafetyHook's
         *          vectored exception handler. A thread already dispatching through the cloned slot can call into the
         *          freed clone, so the caller must guarantee no thread is calling a hooked method on @p object across
         *          create/remove, and that @p object outlives the hook. The vptr must also stay stable for the hook's
         *          lifetime; if the game reconstructs the object in place (rewriting its vptr) the hook is silently
         *          lost.
         */
        [[nodiscard]] std::expected<std::string, HookError> create_vmt_hook(std::string_view name, void *object);

        /**
         * @brief Configurable VMT hook creation, symmetric with the inline hook's @ref create_inline_hook overload.
         * @details Single source of truth for VMT hook policy. The single-argument overload above is a thin delegating
         *          wrapper around this one with a default-constructed @ref VmtHookConfig, so call sites that only need
         *          a name and an object compile and behave exactly as before.
         * @param name A unique, descriptive name for the VMT hook.
         * @param object Pointer to the polymorphic object whose vptr will be replaced.
         * @param cfg VMT policy (fail-if-already-hooked, pre-flight slot decoding).
         * @return std::expected<std::string, HookError> The hook name if successful. @ref HookError::HookAlreadyExists
         *         is returned when @p cfg.fail_if_already_hooked is set and the object's vptr already points at a
         *         vtable cloned by this HookManager. @ref HookError::InvalidObject is returned when
         *         @p cfg.fail_on_non_function_pointer is set and the pre-flight decoder rejects the first byte of
         *         the vtable, and also when either flag is set and the object's vptr or vtable is unreadable.
         */
        [[nodiscard]] std::expected<std::string, HookError> create_vmt_hook(std::string_view name, void *object,
                                                                            const VmtHookConfig &cfg);

        /**
         * @brief Hooks a specific virtual method by index in a named VMT hook.
         * @tparam T The type of the destination function (function pointer or member function pointer).
         * @param vmt_name The name of the VMT hook (from create_vmt_hook).
         * @param method_index The zero-based vtable index of the method to hook.
         * @param destination The replacement function.
         * @return std::expected<size_t, HookError> The method index if successful, error code otherwise.
         */
        template <typename T>
        [[nodiscard]] std::expected<size_t, HookError> hook_vmt_method(std::string_view vmt_name, size_t method_index,
                                                                       T destination)
        {
            if (m_shutdown_called.load(std::memory_order_acquire))
            {
                m_logger.error("HookManager: Shutdown in progress. Cannot hook VMT method on '{}'.", vmt_name);
                return std::unexpected(HookError::ShutdownInProgress);
            }
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant hook_vmt_method('{}'/{}) from within a with_*/try_with_* "
                               "callback rejected; defer hook mutation until the callback returns.",
                               vmt_name, method_index);
                return std::unexpected(HookError::ReentrantCallRejected);
            }

            auto [result,
                  deferred_logs] = [&]() -> std::pair<std::expected<size_t, HookError>, std::vector<DeferredLogEntry>>
            {
                std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
                std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);

                if (m_shutdown_called.load(std::memory_order_acquire))
                {
                    return {
                        std::unexpected(HookError::ShutdownInProgress),
                        {{std::format("HookManager: Shutdown in progress. Cannot hook VMT method on '{}'.", vmt_name),
                          LogLevel::Error}}};
                }

                auto vmt_it = m_vmt_hooks.find(vmt_name);
                if (vmt_it == m_vmt_hooks.end())
                {
                    return {std::unexpected(HookError::VmtHookNotFound),
                            {{std::format("HookManager: VMT hook '{}' not found for method hook at index {}.", vmt_name,
                                          method_index),
                              LogLevel::Error}}};
                }

                if (vmt_it->second.has_method_hook(method_index))
                {
                    return {std::unexpected(HookError::MethodAlreadyHooked),
                            {{std::format("HookManager: VMT '{}' method index {} is already hooked.", vmt_name,
                                          method_index),
                              LogLevel::Error}}};
                }

                try
                {
                    auto hook_result = vmt_it->second.vmt_hook().hook_method(method_index, destination);

                    if (!hook_result)
                    {
                        return {std::unexpected(HookError::SafetyHookError),
                                {{std::format("HookManager: Failed to hook VMT '{}' method index {}.", vmt_name,
                                              method_index),
                                  LogLevel::Error}}};
                    }

                    vmt_it->second.add_method_hook(method_index, std::move(hook_result.value()));

                    return {method_index,
                            {{std::format("HookManager: Successfully hooked VMT '{}' method index {}.", vmt_name,
                                          method_index),
                              LogLevel::Info}}};
                }
                catch (const std::exception &e)
                {
                    return {std::unexpected(HookError::UnknownError),
                            {{std::format("HookManager: Exception hooking VMT '{}' method index {}: {}", vmt_name,
                                          method_index, e.what()),
                              LogLevel::Error}}};
                }
                catch (...)
                {
                    return {std::unexpected(HookError::UnknownError),
                            {{std::format("HookManager: Unknown exception hooking VMT '{}' method index {}.", vmt_name,
                                          method_index),
                              LogLevel::Error}}};
                }
            }();

            for (const auto &entry : deferred_logs)
            {
                m_logger.log(entry.level, entry.msg);
            }
            return result;
        }

        /**
         * @brief Removes an entire VMT hook, restoring the original vtable on all applied objects.
         * @details Bulk teardown (remove_all_vmt_hooks, remove_all_hooks, shutdown, destructor) destroys VMT hooks
         *          in reverse creation order so clones layered on the same object unwind safely. Explicit removal
         *          does not reorder for the caller: removing an inner layer while a clone created later on top of it
         *          is still installed frees the clone that the newer hook recorded as its "original", so remove
         *          layered hooks newest-first.
         * @param vmt_name The name of the VMT hook to remove.
         * @return Success if removed, or HookError::VmtHookNotFound.
         */
        [[nodiscard]] std::expected<void, HookError> remove_vmt_hook(std::string_view vmt_name);

        /**
         * @brief Removes a single method hook from a VMT, restoring the original method.
         * @param vmt_name The name of the VMT hook.
         * @param method_index The vtable index of the method to unhook.
         * @return Success if removed, or a HookError describing the failure.
         */
        [[nodiscard]] std::expected<void, HookError> remove_vmt_method(std::string_view vmt_name, size_t method_index);

        /**
         * @brief Applies the cloned (hooked) vtable to an additional object.
         * @param vmt_name The name of the VMT hook.
         * @param object The object to apply the hooked vtable to.
         * @return true if the VMT hook was found and applied, false otherwise.
         */
        [[nodiscard]] bool apply_vmt_hook(std::string_view vmt_name, void *object);

        /**
         * @brief Configurable form of @ref apply_vmt_hook, symmetric with @ref create_vmt_hook.
         * @details The two-argument overload above is a thin delegating wrapper that uses a default-constructed
         *          @ref VmtHookConfig, preserving the historical permissive apply semantics (apply still returns
         *          false on shutdown, a null object, an unknown name, or an apply exception).
         * @param vmt_name The name of the VMT hook whose cloned vtable should be installed.
         * @param object The object to apply the cloned vtable to.
         * @param cfg Apply policy. @p cfg.fail_if_already_hooked lets a mod refuse to install its vtable on an
         *            object that is already on a clone from this HookManager (a re-apply of the same clone is a
         *            no-op for SafetyHook; the guard exists for symmetry and for callers that want a single
         *            create/apply that is a no-op on a re-invocation). @p cfg.fail_on_non_function_pointer re-runs
         *            the pre-flight decoder against the vtable currently installed on the object (the one about to
         *            be replaced).
         * @return true if the VMT hook was found and applied, false otherwise.
         */
        [[nodiscard]] bool apply_vmt_hook(std::string_view vmt_name, void *object, const VmtHookConfig &cfg);

        /**
         * @brief Removes the hooked vtable from a specific object, restoring its original vptr.
         * @param vmt_name The name of the VMT hook.
         * @param object The object to restore.
         * @return true if the VMT hook was found and the object was restored, false otherwise.
         */
        [[nodiscard]] bool remove_vmt_from_object(std::string_view vmt_name, void *object);

        /**
         * @brief Removes all VMT hooks, restoring original vtables on all applied objects.
         */
        void remove_all_vmt_hooks();

        /**
         * @brief Returns the names of all active VMT hooks.
         * @return std::vector<std::string> Vector containing the names of the VMT hooks.
         */
        [[nodiscard]] std::vector<std::string> get_vmt_hook_names() const;

        /**
         * @brief Safely accesses a VmHook (method hook) within a named VMT hook.
         * @details The callback is invoked while the hook registry is held under a reader lock.
         * @warning Do not call HookManager mutators, teardown entry points, or a nested with_* or try_with_* accessor
         *          from the callback (each checks the reentrancy guard and fails closed). Queue mutations and apply
         *          them after the callback returns.
         * @tparam F Callable type accepting (safetyhook::VmHook&) and returning a value.
         * @param vmt_name The name of the VMT hook.
         * @param method_index The vtable index of the method hook.
         * @param fn The callback to invoke with the VmHook reference.
         * @return std::optional<R> The callback's return value, or std::nullopt if not found.
         */
        template <typename F>
            requires std::invocable<F, safetyhook::VmHook &> &&
                     (!std::is_void_v<std::invoke_result_t<F, safetyhook::VmHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, safetyhook::VmHook &>>)
        [[nodiscard]] auto with_vmt_method(std::string_view vmt_name, size_t method_index, F &&fn)
            -> std::optional<std::invoke_result_t<F, safetyhook::VmHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_vmt_method('{}'/{})!", vmt_name,
                               method_index);
                return std::nullopt;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
            ReentrancyGuard guard(get_reentrancy_guard());
            auto vmt_it = m_vmt_hooks.find(vmt_name);
            if (vmt_it != m_vmt_hooks.end())
            {
                auto *vm_hook = vmt_it->second.get_method_hook(method_index);
                if (vm_hook)
                {
                    return std::invoke(std::forward<F>(fn), *vm_hook);
                }
            }
            return std::nullopt;
        }

        /**
         * @brief Safely accesses a VmHook for a void-returning callback.
         * @details Same locking and reentrancy semantics as the value-returning overload.
         * @warning Do not call HookManager mutators, teardown entry points, or a nested with_* or try_with_* accessor
         *          from the callback (each checks the reentrancy guard and fails closed). Queue mutations and apply
         *          them after the callback returns.
         * @param vmt_name The name of the VMT hook.
         * @param method_index The vtable index of the method hook.
         * @param fn The void-returning callback to invoke with the VmHook reference.
         * @return true if the method hook was found and the callback was invoked, false otherwise.
         */
        template <typename F>
            requires std::invocable<F, safetyhook::VmHook &> &&
                     std::is_void_v<std::invoke_result_t<F, safetyhook::VmHook &>>
        [[nodiscard]] bool with_vmt_method(std::string_view vmt_name, size_t method_index, F &&fn)
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_vmt_method('{}'/{})!", vmt_name,
                               method_index);
                return false;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
            ReentrancyGuard guard(get_reentrancy_guard());
            auto vmt_it = m_vmt_hooks.find(vmt_name);
            if (vmt_it != m_vmt_hooks.end())
            {
                auto *vm_hook = vmt_it->second.get_method_hook(method_index);
                if (vm_hook)
                {
                    std::invoke(std::forward<F>(fn), *vm_hook);
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Reports whether this manager patches @p target_address.
         * @details Inline and mid hooks both patch the target prologue, so both are reported here. The query walks only
         *          this HookManager's registry; hooks installed by other statically-linked DMK consumers in the same
         *          process are not visible.
         *
         *          Use this to short-circuit redundant create_inline_hook or create_mid_hook calls. To detect hooks
         *          installed outside this manager, pass HookConfig::fail_if_already_hooked during creation.
         * @param target_address Function address to query.
         * @return true if a managed inline or mid hook already targets this address.
         */
        [[nodiscard]] bool is_target_already_hooked(uintptr_t target_address) const noexcept;

        /**
         * @brief Removes a hook identified by its name.
         * @details Bulk teardown (remove_all_hooks, shutdown, destructor) disables and destroys hooks in reverse
         *          creation order so hooks layered on one target address unwind safely. Explicit single removal does
         *          not reorder for the caller: removing an older hook while a newer hook layered on the same address is
         *          still installed restores the prologue to the original bytes underneath the newer hook, leaving its
         *          entry jump pointing into a trampoline that is about to be freed. Remove layered hooks newest-first.
         * @param hook_id The name of the hook to remove.
         * @return Success if removed, or HookError::HookNotFound.
         */
        [[nodiscard]] std::expected<void, HookError> remove_hook(std::string_view hook_id);

        /**
         * @brief Removes all hooks currently managed by this HookManager instance.
         * @details Uses two-phase removal: disables all hooks under a shared lock first, then clears the maps under an
         *          exclusive lock. Both phases walk the hooks in reverse creation order so hooks layered on one target
         *          address unwind newest-first and each prologue restore writes onto still-valid bytes rather than into
         *          a freed trampoline. The shared phase lets DetourModKit's own with_* readers finish before Hook
         *          storage is destroyed. SafetyHook can relocate threads caught in the patched prologue, but it cannot
         *          drain threads already running the detour or trampoline body; callers must quiesce the hooked
         *          function during planned teardown to close that residual window.
         *
         *          After clearing, resets the internal shutdown flag to false, allowing subsequent create_*_hook()
         *          calls to succeed for hot-reload workflows.
         */
        void remove_all_hooks() noexcept;

        /**
         * @brief Enables a previously disabled hook.
         * @details Idempotent: enabling an already-active hook returns success. Returns HookError::InvalidHookState
         *          only when the hook is in a transitional state (Enabling or Disabling). Other HookError values
         *          indicate lookup or SafetyHook failures.
         * @param hook_id The name of the hook to enable.
         * @return Success if the hook is now active (or was already active), or a HookError describing the failure.
         */
        [[nodiscard]] std::expected<void, HookError> enable_hook(std::string_view hook_id);

        /**
         * @brief Disables an active hook temporarily without removing it.
         * @details Idempotent: disabling an already-disabled hook returns success. Returns HookError::InvalidHookState
         *          only when the hook is in a transitional state (Enabling or Disabling). Other HookError values
         *          indicate lookup or SafetyHook failures.
         * @param hook_id The name of the hook to disable.
         * @return Success if the hook is now disabled (or was already disabled), or a HookError describing the failure.
         */
        [[nodiscard]] std::expected<void, HookError> disable_hook(std::string_view hook_id);

        /**
         * @brief Enables several hooks by name in a single locked pass.
         * @details Convenience for startup and hot-reload phases that toggle many hooks at once: takes the manager's
         *          locks once for the whole batch instead of once per hook. An unknown id is warned and skipped, not
         *          fatal, and an already-active hook counts as a success (enable is idempotent). This is an ergonomic
         *          wrapper, not a performance optimization over repeated enable_hook calls: the SafetyHook backend
         *          installs via a vectored exception handler and does not suspend threads, so there is no process-wide
         *          suspension to amortize.
         * @param hook_ids The names of the hooks to enable.
         * @return The number of hooks now active.
         */
        [[nodiscard]] std::size_t enable_hooks(std::span<const std::string_view> hook_ids);

        /**
         * @brief Disables several hooks by name in a single locked pass.
         * @details The disable counterpart to @ref enable_hooks: locks once, warns and skips unknown ids, and counts an
         *          already-disabled hook as a success (disable is idempotent). Ergonomics only (see @ref enable_hooks).
         * @param hook_ids The names of the hooks to disable.
         * @return The number of hooks now disabled.
         */
        [[nodiscard]] std::size_t disable_hooks(std::span<const std::string_view> hook_ids);

        /**
         * @brief Enables every hook currently managed by this instance in one pass.
         * @return The number of hooks now active.
         */
        [[nodiscard]] std::size_t enable_all_hooks();

        /**
         * @brief Disables every hook currently managed by this instance in one pass.
         * @return The number of hooks now disabled.
         */
        [[nodiscard]] std::size_t disable_all_hooks();

        /**
         * @brief Retrieves the current status of a hook.
         * @param hook_id The name of the hook.
         * @return std::optional<HookStatus> The current status, or std::nullopt if not found.
         */
        [[nodiscard]] std::optional<HookStatus> get_hook_status(std::string_view hook_id) const;

        /**
         * @brief Gets a summary of hook counts categorized by their status.
         * @return std::unordered_map<HookStatus, size_t> Map of statuses to counts.
         */
        [[nodiscard]] std::unordered_map<HookStatus, size_t> get_hook_counts() const;

        /**
         * @brief Retrieves a list of hook names.
         * @param status_filter Optional status filter for returned hooks.
         * @return std::vector<std::string> Vector containing the names of the hooks.
         */
        [[nodiscard]] std::vector<std::string>
        get_hook_ids(std::optional<HookStatus> status_filter = std::nullopt) const;

        // clang-format off
        /**
         * @brief Safely accesses an InlineHook by its ID while holding the internal lock.
         * @details The callback receives an InlineHook reference while the hook registry is held under a reader lock.
         * @warning Do not call HookManager mutators, teardown entry points, or a nested with_* or try_with_* accessor
         *          from the callback. The callback holds m_hooks_mutex shared: create/remove/teardown paths acquire it
         *          exclusively and toggle paths re-acquire it shared (UB on a non-recursive lock), while nested
         *          accessors check the reentrancy guard and fail closed. Queue mutations and apply them after the
         *          callback returns.
         * @tparam F Callable type accepting (InlineHook&) and returning a value.
         * @param hook_id The name of the inline hook.
         * @param fn The callback to invoke with the hook reference.
         * @return The callback's return value, or std::nullopt if the hook was not found.
         */
        // clang-format on
        template <typename F>
            requires std::invocable<F, InlineHook &> && (!std::is_void_v<std::invoke_result_t<F, InlineHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, InlineHook &>>)
        [[nodiscard]] auto with_inline_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_inline_hook('{}')! "
                               "Callback holding m_hooks_mutex must not call HookManager mutators or teardown methods. "
                               "Perform mutations outside the callback or use an asynchronous operation.",
                               hook_id);
                return std::nullopt;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
            ReentrancyGuard guard(get_reentrancy_guard());
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Inline)
            {
                return std::invoke(std::forward<F>(fn), static_cast<InlineHook &>(*it->second));
            }
            return std::nullopt;
        }

        /**
         * @brief Safely accesses an InlineHook by its ID for a void-returning callback.
         * @details Same locking and reentrancy semantics as the value-returning overload.
         * @param hook_id The name of the inline hook.
         * @param fn The void-returning callback to invoke with the hook reference.
         * @return true if the hook was found and the callback was invoked, false otherwise.
         */
        template <typename F>
            requires std::invocable<F, InlineHook &> && std::is_void_v<std::invoke_result_t<F, InlineHook &>>
        [[nodiscard]] bool with_inline_hook(std::string_view hook_id, F &&fn)
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_inline_hook('{}')! "
                               "Callback holding m_hooks_mutex must not call HookManager mutators or teardown methods. "
                               "Perform mutations outside the callback or use an asynchronous operation.",
                               hook_id);
                return false;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
            ReentrancyGuard guard(get_reentrancy_guard());
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Inline)
            {
                std::invoke(std::forward<F>(fn), static_cast<InlineHook &>(*it->second));
                return true;
            }
            return false;
        }

        /**
         * @brief Try-safe access to an InlineHook by its ID using a non-blocking lock.
         * @details Provides a non-blocking alternative to with_inline_hook(). The callback is invoked only if the lock
         *          is immediately acquired via std::try_to_lock. Note: try_to_lock only avoids blocking on initial
         *          acquisition - it does NOT make callbacks safe to re-enter HookManager mutators or teardown methods
         *          that also acquire the same non-recursive mutex. If a callback needs to call those methods, it must
         *          release the lock first or perform those calls asynchronously to avoid deadlock. See with_inline_hook
         *          for the blocking analogue.
         * @param hook_id The name of the inline hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value. Returns std::nullopt if either the lock could not be
         *         acquired or the hook was not found.
         */
        template <typename F>
            requires std::invocable<F, InlineHook &> && (!std::is_void_v<std::invoke_result_t<F, InlineHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, InlineHook &>>)
        [[nodiscard]] auto try_with_inline_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in try_with_inline_hook('{}')! "
                               "Callback holding m_hooks_mutex must not call HookManager mutators or teardown methods. "
                               "Perform mutations outside the callback or use an asynchronous operation.",
                               hook_id);
                return std::nullopt;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex, std::try_to_lock);
            if (!lock.owns_lock())
            {
                return std::nullopt;
            }
            ReentrancyGuard guard(get_reentrancy_guard());
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Inline)
            {
                return std::invoke(std::forward<F>(fn), static_cast<InlineHook &>(*it->second));
            }
            return std::nullopt;
        }

        // clang-format off
        /**
         * @brief Safely accesses a MidHook by its ID while holding the internal lock.
         * @details The callback receives a MidHook reference while the hook registry is held under a reader lock.
         * @warning Do not call HookManager mutators, teardown entry points, or a nested with_* or try_with_* accessor
         *          from the callback. The callback holds m_hooks_mutex shared: create/remove/teardown paths acquire it
         *          exclusively and toggle paths re-acquire it shared (UB on a non-recursive lock), while nested
         *          accessors check the reentrancy guard and fail closed. Queue mutations and apply them after the
         *          callback returns.
         * @tparam F Callable type accepting (MidHook&) and returning a value.
         * @param hook_id The name of the mid hook.
         * @param fn The callback to invoke with the hook reference.
         * @return The callback's return value, or std::nullopt if the hook was not found.
         */
        // clang-format on
        template <typename F>
            requires std::invocable<F, MidHook &> && (!std::is_void_v<std::invoke_result_t<F, MidHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, MidHook &>>)
        [[nodiscard]] auto with_mid_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_mid_hook('{}')! "
                               "Callback holding m_hooks_mutex must not call HookManager mutators or teardown methods. "
                               "Perform mutations outside the callback or use an asynchronous operation.",
                               hook_id);
                return std::nullopt;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
            ReentrancyGuard guard(get_reentrancy_guard());
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Mid)
            {
                return std::invoke(std::forward<F>(fn), static_cast<MidHook &>(*it->second));
            }
            return std::nullopt;
        }

        /**
         * @brief Safely accesses a MidHook by its ID for a void-returning callback.
         * @details Same locking and reentrancy semantics as the value-returning overload.
         * @param hook_id The name of the mid hook.
         * @param fn The void-returning callback to invoke with the hook reference.
         * @return true if the hook was found and the callback was invoked, false otherwise.
         */
        template <typename F>
            requires std::invocable<F, MidHook &> && std::is_void_v<std::invoke_result_t<F, MidHook &>>
        [[nodiscard]] bool with_mid_hook(std::string_view hook_id, F &&fn)
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_mid_hook('{}')! "
                               "Callback holding m_hooks_mutex must not call HookManager mutators or teardown methods. "
                               "Perform mutations outside the callback or use an asynchronous operation.",
                               hook_id);
                return false;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
            ReentrancyGuard guard(get_reentrancy_guard());
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Mid)
            {
                std::invoke(std::forward<F>(fn), static_cast<MidHook &>(*it->second));
                return true;
            }
            return false;
        }

        /**
         * @brief Try-safe access to a MidHook by its ID using a non-blocking lock.
         * @details Provides a non-blocking alternative to with_mid_hook(). The callback is invoked only if the lock is
         *          immediately acquired via std::try_to_lock. Note: try_to_lock only avoids blocking on initial
         *          acquisition - it does NOT make callbacks safe to re-enter HookManager mutators or teardown methods
         *          that also acquire the same non-recursive mutex. If a callback needs to call those methods, it must
         *          release the lock first or perform those calls asynchronously to avoid deadlock. See with_mid_hook
         *          for the blocking analogue.
         * @param hook_id The name of the mid hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value. Returns std::nullopt if either the lock could not be
         *         acquired or the hook was not found.
         */
        template <typename F>
            requires std::invocable<F, MidHook &> && (!std::is_void_v<std::invoke_result_t<F, MidHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, MidHook &>>)
        [[nodiscard]] auto try_with_mid_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in try_with_mid_hook('{}')! "
                               "Callback holding m_hooks_mutex must not call HookManager mutators or teardown methods. "
                               "Perform mutations outside the callback or use an asynchronous operation.",
                               hook_id);
                return std::nullopt;
            }
            std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex, std::try_to_lock);
            if (!lock.owns_lock())
            {
                return std::nullopt;
            }
            ReentrancyGuard guard(get_reentrancy_guard());
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Mid)
            {
                return std::invoke(std::forward<F>(fn), static_cast<MidHook &>(*it->second));
            }
            return std::nullopt;
        }

    private:
        /** @brief Internal log entry used to defer logging outside held locks. */
        struct DeferredLogEntry
        {
            std::string msg;
            LogLevel level;
        };
        explicit HookManager(Logger &logger = Logger::get_instance());

        mutable detail::SrwSharedMutex m_hooks_mutex;
        detail::HookMap m_hooks;
        detail::VmtHookMap m_vmt_hooks;

        /**
         * @brief VMT hook names in creation order, maintained under m_hooks_mutex alongside m_vmt_hooks.
         * @details Bulk teardown walks this vector in reverse via clear_vmt_hooks_locked() so clones layered on the
         *          same object are destroyed newest-first instead of in unordered_map bucket order.
         */
        std::vector<std::string> m_vmt_creation_order;

        /**
         * @brief Inline and mid hook names in creation order, maintained under m_hooks_mutex alongside m_hooks.
         * @details Teardown disables and destroys hooks by walking this vector in reverse (see
         *          disable_hooks_reverse_order_locked() and clear_hooks_locked()) so hooks layered on one target
         *          address unwind newest-first. SafetyHook saves the live prologue at create time, so a second hook on
         *          a target stores "jmp -> first detour" as its own original bytes; restoring oldest-first would
         *          rewrite the entry to jump into the older hook's about-to-be-freed trampoline. A single global
         *          reverse walk yields the required per-address LIFO because the hooks on any one address are a
         *          subsequence of the global creation order.
         */
        std::vector<std::string> m_hook_creation_order;

        Logger &m_logger;
        std::shared_ptr<safetyhook::Allocator> m_allocator;
        std::atomic<bool> m_shutdown_called{false};

        /**
         * @brief Gate that mutators (create_*_hook, enable_hook, disable_hook, remove_hook) acquire shared on entry,
         *        allowing shutdown/remove_all_hooks to acquire exclusive to block new work. Teardown serialization uses
         *        compare_exchange_strong on m_shutdown_called rather than a separate mutex.
         */
        mutable detail::SrwSharedMutex m_mutator_gate;

        /**
         * @brief Returns the thread-local reentrancy depth counter.
         * @details Declared const so the const read-only query accessors can consult the guard. The counter is
         *          thread-local and independent of object state, so const is honest here.
         */
        [[nodiscard]] int &get_reentrancy_guard() const noexcept
        {
            thread_local int reentrancy_counter{0};
            return reentrancy_counter;
        }

        struct ReentrancyGuard
        {
            int &counter;
            explicit ReentrancyGuard(int &cnt) noexcept : counter(cnt) { ++counter; }
            ~ReentrancyGuard() noexcept { --counter; }
            ReentrancyGuard(const ReentrancyGuard &) = delete;
            ReentrancyGuard &operator=(const ReentrancyGuard &) = delete;
            ReentrancyGuard(ReentrancyGuard &&) = delete;
            ReentrancyGuard &operator=(ReentrancyGuard &&) = delete;
        };

        // clang-format off
        /**
         * @brief Acquires m_hooks_mutex shared, or returns a disengaged lock when reentrant.
         * @details A with_* or try_with_* callback already holds m_hooks_mutex shared on this thread and has bumped the
         *          reentrancy guard. Re-locking the non-recursive reader/writer mutex from the same thread is undefined
         *          behavior and can deadlock if a writer is queued between the two acquisitions. A const query accessor
         *          invoked from inside such a callback must read under the lock the callback already holds instead of
         *          taking a second shared lock. When not reentrant, the returned lock owns m_hooks_mutex for the
         *          caller's scope exactly as a direct shared_lock would.
         * @return An engaged shared_lock when guard == 0, otherwise a disengaged one.
         */
        // clang-format on
        [[nodiscard]] std::shared_lock<detail::SrwSharedMutex> lock_hooks_shared_reentrant() const
        {
            if (get_reentrancy_guard() > 0)
            {
                return std::shared_lock<detail::SrwSharedMutex>{};
            }
            return std::shared_lock<detail::SrwSharedMutex>(m_hooks_mutex);
        }

        std::string error_to_string(const safetyhook::InlineHook::Error &err) const;
        std::string error_to_string(const safetyhook::MidHook::Error &err) const;

        /**
         * @brief Enables or disables one already-located hook under the held locks.
         * @details Shared body of the batch toggle methods. The caller must hold m_mutator_gate and m_hooks_mutex (both
         *          shared) and must have confirmed the manager is not shutting down. Logs the outcome exactly like the
         *          single-hook enable_hook / disable_hook path.
         * @param hook_id The hook's name, used only for logging.
         * @param hook The hook to toggle.
         * @param enable true to enable, false to disable.
         * @param logs Sink for the outcome message; emitted after the locks release so no logger sink I/O happens
         *             inside the critical section.
         * @return true if the hook is now in the requested state.
         */
        [[nodiscard]] bool toggle_hook_locked(std::string_view hook_id, Hook &hook, bool enable,
                                              std::vector<DeferredLogEntry> &logs);

        [[nodiscard]] bool hook_id_exists_locked(std::string_view hook_id) const
        {
            return m_hooks.find(hook_id) != m_hooks.end();
        }

        [[nodiscard]] bool vmt_hook_exists_locked(std::string_view name) const
        {
            return m_vmt_hooks.find(name) != m_vmt_hooks.end();
        }

        /**
         * @brief Destroys every VMT hook entry in reverse creation order and empties the registry.
         * @details When two hooks layer on the same object, the newer hook records the older hook's clone as its
         *          "original" vtable. SafetyHook::VmtHook::destroy frees a hook's clone allocation unconditionally
         *          but restores an object's vptr only when it still points at that hook's own clone, so destroying
         *          the older hook first would leave the newer hook to restore the object's vptr to freed memory.
         *          Newest-first destruction unwinds the layers so every restore writes a vptr that is still alive.
         * @note Must be called with m_hooks_mutex held exclusively.
         */
        void clear_vmt_hooks_locked() noexcept;

        /**
         * @brief Disables every inline and mid hook in reverse creation order.
         * @details Phase 1 of teardown. SafetyHook::InlineHook::disable() copies each hook's saved prologue bytes back
         *          over the target; for hooks layered on one address the newer hook saved "jmp -> older detour" as its
         *          original, so it must restore first (returning the prologue to that jump) before the older hook
         *          restores the true original bytes. Disabling oldest-first would instead leave the live prologue
         *          jumping into the older hook's trampoline, which clear_hooks_locked() then frees -- a use-after-free.
         *          Hooks on distinct addresses are independent, so one global reverse-creation-order walk yields the
         *          correct per-address LIFO for all of them at once.
         * @note Must be called with m_hooks_mutex held (shared is sufficient: this mutates Hook state, not the map).
         */
        void disable_hooks_reverse_order_locked() noexcept;

        /**
         * @brief Destroys every inline and mid hook in reverse creation order and empties the registry.
         * @details Phase 2 of teardown. By the time this runs disable_hooks_reverse_order_locked() has already restored
         *          every prologue, so destruction only frees trampolines; freeing them newest-first keeps the order
         *          uniform with the disable phase and with clear_vmt_hooks_locked() rather than depending on
         *          unordered_map bucket order.
         * @note Must be called with m_hooks_mutex held exclusively.
         */
        void clear_hooks_locked() noexcept;

        /**
         * @brief Returns the name of the VMT hook whose cloned vptr matches @p vptr, or nullptr if none.
         * @details Walks the live VMT registry under the held m_hooks_mutex shared or exclusive lock and compares the
         *          recorded cloned-vptr base. The check is O(N) over the (small) registry and is the only reliable way
         *          to detect "object is already on a clone installed by this HookManager" without poking at
         *          SafetyHook's private VmtHook layout. The caller-supplied @p vptr must already be plausibly a
         *          userspace address; the comparison is a single qword, so no extra bounds work is needed here.
         * @note Must be called with m_hooks_mutex held (shared or exclusive). The read-only accessors that need the
         *       reentrancy-aware lock use the same primitive.
         */
        [[nodiscard]] const std::string *find_vmt_owner_of_vptr_locked(std::uintptr_t vptr) const noexcept;

        /**
         * @brief Returns the managed hook installed at @p target_address, or nullptr if none.
         * @details Inline and mid hooks at the same address patch the same prologue bytes and share the teardown-order
         *          hazard. The registry check is exact, unlike the prologue-byte heuristic used for foreign hooks.
         * @note Must be called with m_hooks_mutex held (shared or exclusive).
         */
        [[nodiscard]] const std::string *find_hook_owner_of_target_locked(uintptr_t target_address) const noexcept;

        /**
         * @brief Decodes the first few bytes of @p slot_value to decide if it looks like a callable function body.
         * @details Mirrors the inline pre-flight's detail::decode_* blacklist but is applied to a VMT slot value
         *          directly so the VMT path does not need to round-trip through the scanner module. The first byte
         *          is read with a single SEH-guarded byte load (no further decoding); when the first byte is one of
         *          0xCC/0xCD/0xC2/0xC3/0x00 the slot is rejected, when it is 0xEB/0xE9 the next 1-4 bytes are
         *          inspected to see if the relative jump target is inside the same module per GetModuleHandleEx
         *          HMODULE identity (heuristic for a jump stub). Everything else passes. Allocation-free, noexcept,
         *          no logger dependency.
         * @param slot_value The first pointer-sized value read from the VMT slot.
         * @return true when the slot is a real function pointer (or a tail-call to outside the same module),
         *         false when it is a breakpoint, bare RET, or same-module jump stub.
         */
        [[nodiscard]] static bool looks_like_function_vmt_slot(std::uintptr_t slot_value) noexcept;
    };

    /**
     * @brief Convenience wrapper that installs an inline hook by direct address.
     * @details Forwards every argument to HookManager::create_inline_hook. Returns the registered hook name on success,
     *          std::nullopt on failure. Diagnostic logging on failure is delegated to the underlying create_inline_hook
     *          call, which already formats a richly-detailed Error line for every failure code; this wrapper does not
     *          emit a duplicate.
     */
    [[nodiscard]] inline std::optional<std::string> try_install_inline(std::string_view name, uintptr_t target_address,
                                                                       void *detour_function,
                                                                       void **original_trampoline,
                                                                       const HookConfig &config = HookConfig())
    {
        auto result = HookManager::get_instance().create_inline_hook(name, target_address, detour_function,
                                                                     original_trampoline, config);
        if (result)
        {
            return *result;
        }
        return std::nullopt;
    }

    /**
     * @brief Convenience wrapper that installs an inline hook by AOB scan.
     * @details Diagnostic logging on failure is delegated to the underlying create_inline_hook_aob call
     *          (pattern-resolution failures and create_inline_hook failures both emit their own Error line), so this
     *          wrapper does not emit a duplicate. The AOB scan is page-filtered exactly as create_inline_hook_aob
     *          documents: a full SizeOfImage span containing a guard or no-access section is safe to pass.
     */
    [[nodiscard]] inline std::optional<std::string>
    try_install_inline_aob(std::string_view name, uintptr_t module_base, size_t module_size,
                           std::string_view aob_pattern, std::ptrdiff_t aob_offset, void *detour_function,
                           void **original_trampoline, const HookConfig &config = HookConfig())
    {
        auto result = HookManager::get_instance().create_inline_hook_aob(
            name, module_base, module_size, aob_pattern, aob_offset, detour_function, original_trampoline, config);
        if (result)
        {
            return *result;
        }
        return std::nullopt;
    }

    /**
     * @brief Convenience wrapper that installs a mid-function hook by direct address.
     * @details Diagnostic logging on failure is delegated to the underlying create_mid_hook call.
     */
    [[nodiscard]] inline std::optional<std::string> try_install_mid(std::string_view name, uintptr_t target_address,
                                                                    safetyhook::MidHookFn detour_function,
                                                                    const HookConfig &config = HookConfig())
    {
        auto result = HookManager::get_instance().create_mid_hook(name, target_address, detour_function, config);
        if (result)
        {
            return *result;
        }
        return std::nullopt;
    }

    /**
     * @brief Convenience wrapper that installs a mid-function hook by AOB scan.
     * @details Diagnostic logging on failure is delegated to the underlying create_mid_hook_aob call. The AOB scan is
     *          page-filtered exactly as create_mid_hook_aob documents: a full SizeOfImage span containing a guard or
     *          no-access section is safe to pass.
     */
    [[nodiscard]] inline std::optional<std::string>
    try_install_mid_aob(std::string_view name, uintptr_t module_base, size_t module_size, std::string_view aob_pattern,
                        std::ptrdiff_t aob_offset, safetyhook::MidHookFn detour_function,
                        const HookConfig &config = HookConfig())
    {
        auto result = HookManager::get_instance().create_mid_hook_aob(name, module_base, module_size, aob_pattern,
                                                                      aob_offset, detour_function, config);
        if (result)
        {
            return *result;
        }
        return std::nullopt;
    }
} // namespace DetourModKit

#endif // DETOURMODKIT_HOOK_MANAGER_HPP
