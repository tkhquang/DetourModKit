#ifndef DETOURMODKIT_HOOK_MANAGER_HPP
#define DETOURMODKIT_HOOK_MANAGER_HPP

#include <string>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <optional>
#include <expected>
#include <string_view>
#include <span>
#include <type_traits>
#include <concepts>
#include <atomic>
#include <utility>
#include <format>

#include "safetyhook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/scanner.hpp"
#include "DetourModKit/format.hpp"

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
         * @brief When true, refuse to inline-hook a target whose first bytes already encode a JMP outside the target's
         *        module.
         * @details With the default (false) a warning is logged but the hook proceeds (SafetyHook layers trampolines on
         *          top of existing inline hooks). Set to true for strict mods that never want to install a second hook
         *          behind another mod's.
         */
        bool fail_if_already_hooked = false;
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
        virtual ~Hook() = default;

        const std::string &get_name() const noexcept { return m_name; }
        HookType get_type() const noexcept { return m_type; }
        uintptr_t get_target_address() const noexcept { return m_target_address; }
        HookStatus get_status() const noexcept { return m_status.load(std::memory_order_acquire); }

        /**
         * @brief Enables the hook.
         * @return Success if the hook was enabled or already active. On failure, the
         *         HookError indicates the reason (SafetyHookError, EnableFailed, InvalidHookState).
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
         * @return Success if the hook was disabled or already disabled. On failure, the
         *         HookError indicates the reason (SafetyHookError, DisableFailed, InvalidHookState).
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

        static constexpr std::string_view status_to_string(HookStatus status) noexcept
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

        static constexpr std::string_view error_to_string(HookError error) noexcept
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
                return "Target address is already inline-hooked by another module";
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
        template <typename T> T get_original() const noexcept
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
        safetyhook::MidHookFn get_destination() const noexcept
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
             */
            VmtHookEntry(std::string name, safetyhook::VmtHook vmt_hook)
                : m_name(std::move(name)), m_vmt_hook(std::move(vmt_hook))
            {
            }

            /// Returns the registered hook name.
            const std::string &get_name() const noexcept { return m_name; }

            /// Returns the underlying SafetyHook VMT hook.
            safetyhook::VmtHook &vmt_hook() noexcept { return m_vmt_hook; }

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
            safetyhook::VmHook *get_method_hook(size_t index)
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
        void shutdown();

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
         * @warning VMT hooks have no enable/disable: creation swaps the object's vptr to the cloned table and removal
         *          restores it. As with the inline hooks, removal cannot drain a thread that is mid-dispatch through a
         *          hooked slot, so the caller must guarantee no thread is calling a hooked method on @p object across
         *          create/remove, and that @p object outlives the hook. The vptr must also stay stable for the hook's
         *          lifetime; if the game reconstructs the object in place (rewriting its vptr) the hook is silently
         *          lost.
         */
        [[nodiscard]] std::expected<std::string, HookError> create_vmt_hook(std::string_view name, void *object);

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

            auto [result,
                  deferred_logs] = [&]() -> std::pair<std::expected<size_t, HookError>, std::vector<DeferredLogEntry>>
            {
                std::shared_lock<std::shared_mutex> mutator_gate(m_mutator_gate);
                std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

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
        std::vector<std::string> get_vmt_hook_names() const;

        /**
         * @brief Safely accesses a VmHook (method hook) within a named VMT hook.
         * @details The callback is invoked while the shared_mutex is held as a reader.
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
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
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
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
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
         * @brief Reports whether @p target_address already carries an inline hook installed by this HookManager
         *        instance.
         * @details Walks the local hook registry under a shared lock. Local-only by design: hooks installed by other
         *          statically-linked DMK consumers in the same process are not visible.
         *
         *          Use this to short-circuit a redundant create_inline_hook call without parsing the prologue bytes. To
         *          detect inline hooks installed by code outside this HookManager (for example a third-party JMP rel32
         *          written into the prologue) pass
         *          HookConfig::fail_if_already_hooked when creating the hook.
         * @param target_address Function address to query.
         * @return true if a managed inline hook already targets this address.
         */
        [[nodiscard]] bool is_target_already_hooked(uintptr_t target_address) const noexcept;

        /**
         * @brief Removes a hook identified by its name.
         * @param hook_id The name of the hook to remove.
         * @return Success if removed, or HookError::HookNotFound.
         */
        [[nodiscard]] std::expected<void, HookError> remove_hook(std::string_view hook_id);

        /**
         * @brief Removes all hooks currently managed by this HookManager instance.
         * @details Uses two-phase removal: disables all hooks under a shared lock first, then clears the maps under an
         *          exclusive lock. The shared phase lets DetourModKit's own with_* readers finish before Hook storage
         *          is destroyed. SafetyHook can relocate threads caught in the patched prologue, but it cannot drain
         *          threads already running the detour or trampoline body; callers must quiesce the hooked function
         *          during planned teardown to close that residual window.
         *
         *          After clearing, resets the internal shutdown flag to false, allowing subsequent create_*_hook()
         *          calls to succeed for hot-reload workflows.
         */
        void remove_all_hooks();

        /**
         * @brief Enables a previously disabled hook.
         * @details Idempotent: enabling an already-active hook returns success.
         *          Returns HookError::InvalidHookState only when the hook is in a transitional state (Enabling or
         *          Disabling). Other HookError values indicate lookup or SafetyHook failures.
         * @param hook_id The name of the hook to enable.
         * @return Success if the hook is now active (or was already active), or a HookError describing the failure.
         */
        [[nodiscard]] std::expected<void, HookError> enable_hook(std::string_view hook_id);

        /**
         * @brief Disables an active hook temporarily without removing it.
         * @details Idempotent: disabling an already-disabled hook returns success.
         *          Returns HookError::InvalidHookState only when the hook is in a transitional state (Enabling or
         *          Disabling). Other HookError values indicate lookup or SafetyHook failures.
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
        std::unordered_map<HookStatus, size_t> get_hook_counts() const;

        /**
         * @brief Retrieves a list of hook names.
         * @param status_filter Optional status filter for returned hooks.
         * @return std::vector<std::string> Vector containing the names of the hooks.
         */
        std::vector<std::string> get_hook_ids(std::optional<HookStatus> status_filter = std::nullopt) const;

        /**
         * @brief Safely accesses an InlineHook by its ID while holding the internal lock.
         * @details The callback is invoked with a reference to the InlineHook while the shared_mutex is held as a
         *          reader, preventing concurrent removal.
         * @warning DANGER: Any callback holding m_hooks_mutex must NOT call methods that
         *          acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook) because those calls
         *          will deadlock. Perform such mutations outside the callback or use an asynchronous/posted operation
         *          that does not hold m_hooks_mutex.
         * @tparam F Callable type accepting (InlineHook&) and returning a value.
         * @param hook_id The name of the inline hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value, or std::nullopt if hook not found.
         */
        template <typename F>
            requires std::invocable<F, InlineHook &> && (!std::is_void_v<std::invoke_result_t<F, InlineHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, InlineHook &>>)
        [[nodiscard]] auto with_inline_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error(
                    "HookManager: Reentrant callback detected in with_inline_hook('{}')! "
                    "Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock "
                    "(remove_hook, enable_hook, disable_hook, create_*_hook). "
                    "Perform mutations outside the callback or use an asynchronous operation.",
                    hook_id);
                return std::nullopt;
            }
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
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
                m_logger.error(
                    "HookManager: Reentrant callback detected in with_inline_hook('{}')! "
                    "Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock "
                    "(remove_hook, enable_hook, disable_hook, create_*_hook). "
                    "Perform mutations outside the callback or use an asynchronous operation.",
                    hook_id);
                return false;
            }
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
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
         *          is immediately acquired via std::try_to_lock.
         *          Note: try_to_lock only avoids blocking on initial acquisition - it does NOT
         *          make callbacks safe to re-enter HookManager methods that also acquire the same non-recursive mutex
         *          (e.g., enable_hook, disable_hook). If a callback needs to call those methods, it must release the
         *          lock first or perform those calls asynchronously to avoid deadlock. See with_inline_hook for the
         *          blocking analogue.
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
                m_logger.error(
                    "HookManager: Reentrant callback detected in try_with_inline_hook('{}')! "
                    "Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock "
                    "(remove_hook, enable_hook, disable_hook, create_*_hook). "
                    "Perform mutations outside the callback or use an asynchronous operation.",
                    hook_id);
                return std::nullopt;
            }
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex, std::try_to_lock);
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

        /**
         * @brief Safely accesses a MidHook by its ID while holding the internal lock.
         * @details The callback is invoked with a reference to the MidHook while the shared_mutex is held as a reader,
         *          preventing concurrent removal.
         * @warning DANGER: Any callback holding m_hooks_mutex must NOT call methods that
         *          acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook) because those calls
         *          will deadlock. Perform such mutations outside the callback or use an asynchronous/posted operation
         *          that does not hold m_hooks_mutex.
         * @tparam F Callable type accepting (MidHook&) and returning a value.
         * @param hook_id The name of the mid hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value, or std::nullopt if hook not found.
         */
        template <typename F>
            requires std::invocable<F, MidHook &> && (!std::is_void_v<std::invoke_result_t<F, MidHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, MidHook &>>)
        [[nodiscard]] auto with_mid_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error(
                    "HookManager: Reentrant callback detected in with_mid_hook('{}')! "
                    "Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock "
                    "(remove_hook, enable_hook, disable_hook, create_*_hook). "
                    "Perform mutations outside the callback or use an asynchronous operation.",
                    hook_id);
                return std::nullopt;
            }
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
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
                m_logger.error(
                    "HookManager: Reentrant callback detected in with_mid_hook('{}')! "
                    "Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock "
                    "(remove_hook, enable_hook, disable_hook, create_*_hook). "
                    "Perform mutations outside the callback or use an asynchronous operation.",
                    hook_id);
                return false;
            }
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
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
         *          immediately acquired via std::try_to_lock.
         *          Note: try_to_lock only avoids blocking on initial acquisition - it does NOT
         *          make callbacks safe to re-enter HookManager methods that also acquire the same non-recursive mutex
         *          (e.g., enable_hook, disable_hook). If a callback needs to call those methods, it must release the
         *          lock first or perform those calls asynchronously to avoid deadlock. See with_mid_hook for the
         *          blocking analogue.
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
                m_logger.error(
                    "HookManager: Reentrant callback detected in try_with_mid_hook('{}')! "
                    "Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock "
                    "(remove_hook, enable_hook, disable_hook, create_*_hook). "
                    "Perform mutations outside the callback or use an asynchronous operation.",
                    hook_id);
                return std::nullopt;
            }
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex, std::try_to_lock);
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

        mutable std::shared_mutex m_hooks_mutex;
        detail::HookMap m_hooks;
        detail::VmtHookMap m_vmt_hooks;
        Logger &m_logger;
        std::shared_ptr<safetyhook::Allocator> m_allocator;
        std::atomic<bool> m_shutdown_called{false};

        /** @brief Gate that mutators (create_*_hook, enable_hook, disable_hook, remove_hook)
         *  acquire shared on entry, allowing shutdown/remove_all_hooks to acquire exclusive
         *  to block new work. Teardown serialization uses compare_exchange_strong on
         *  m_shutdown_called rather than a separate mutex.
         */
        mutable std::shared_mutex m_mutator_gate;

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

        /**
         * @brief Acquires m_hooks_mutex shared, or returns a disengaged lock when reentrant.
         * @details A with_* or try_with_* callback already holds m_hooks_mutex shared on this thread and has bumped the
         *          reentrancy guard. Re-locking a non-recursive std::shared_mutex from the same thread is undefined
         *          behavior (and can deadlock if a writer is queued between the two acquisitions), so a const query
         *          accessor invoked from inside such a callback must read under the lock the callback already holds
         *          instead of taking a second shared lock. When not reentrant (guard == 0) the returned lock owns
         *          m_hooks_mutex for the caller's scope exactly as a direct shared_lock would.
         * @return An engaged shared_lock when guard == 0, otherwise a disengaged one.
         */
        [[nodiscard]] std::shared_lock<std::shared_mutex> lock_hooks_shared_reentrant() const
        {
            if (get_reentrancy_guard() > 0)
            {
                return std::shared_lock<std::shared_mutex>{};
            }
            return std::shared_lock<std::shared_mutex>(m_hooks_mutex);
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
         * @return true if the hook is now in the requested state.
         */
        [[nodiscard]] bool toggle_hook_locked(std::string_view hook_id, Hook &hook, bool enable);

        [[nodiscard]] bool hook_id_exists_locked(std::string_view hook_id) const
        {
            return m_hooks.find(hook_id) != m_hooks.end();
        }

        [[nodiscard]] bool vmt_hook_exists_locked(std::string_view name) const
        {
            return m_vmt_hooks.find(name) != m_vmt_hooks.end();
        }
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
     *          wrapper does not emit a duplicate.
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
     * @details Diagnostic logging on failure is delegated to the underlying create_mid_hook_aob call.
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
