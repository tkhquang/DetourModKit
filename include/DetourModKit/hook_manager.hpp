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
#include <type_traits>
#include <concepts>
#include <atomic>
#include <cassert>
#include <utility>
#include <format>

#include "safetyhook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/scanner.hpp"
#include "DetourModKit/format.hpp"

namespace DetourModKit
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
        ShutdownInProgress,
        SafetyHookError,
        InvalidObject,
        VmtHookNotFound,
        MethodAlreadyHooked,
        UnknownError
    };

    /**
     * @struct HookConfig
     * @brief Configuration options used during the creation of a new hook.
     */
    struct HookConfig
    {
        bool auto_enable = true;
    };

    /**
     * @class Hook
     * @brief Abstract base class for managed hooks.
     * @details Defines a common interface for interacting with different types of hooks
     *          managed by the HookManager. Implements the Template Method pattern for
     *          enable/disable state management.
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
         * @return true if the hook was successfully enabled or already active, false otherwise.
         * @note Uses atomic CAS for lock-free status transitions. Thread-safe without
         *       requiring external synchronization. Uses an intermediate Enabling state
         *       to prevent other threads from observing a speculative terminal state
         *       while the SafetyHook enable call is in progress.
         */
        [[nodiscard]] bool enable()
        {
            if (!is_impl_valid())
                return false;

            HookStatus expected = HookStatus::Disabled;
            if (!m_status.compare_exchange_strong(expected, HookStatus::Enabling, std::memory_order_acq_rel))
                return expected == HookStatus::Active;

            if (do_enable())
            {
                m_status.store(HookStatus::Active, std::memory_order_release);
                return true;
            }

            m_status.store(HookStatus::Disabled, std::memory_order_release);
            return false;
        }

        /**
         * @brief Disables the hook.
         * @return true if the hook was successfully disabled or already disabled, false otherwise.
         * @note Uses atomic CAS for lock-free status transitions. Thread-safe without
         *       requiring external synchronization. Uses an intermediate Disabling state
         *       to prevent other threads from observing a speculative terminal state
         *       while the SafetyHook disable call is in progress.
         */
        [[nodiscard]] bool disable()
        {
            if (!is_impl_valid())
                return false;

            HookStatus expected = HookStatus::Active;
            if (!m_status.compare_exchange_strong(expected, HookStatus::Disabling, std::memory_order_acq_rel))
                return expected == HookStatus::Disabled;

            if (do_disable())
            {
                m_status.store(HookStatus::Disabled, std::memory_order_release);
                return true;
            }

            m_status.store(HookStatus::Active, std::memory_order_release);
            return false;
        }

        bool is_enabled() const noexcept { return m_status.load(std::memory_order_acquire) == HookStatus::Active; }

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
            case HookError::ShutdownInProgress:
                return "Shutdown in progress";
            case HookError::SafetyHookError:
                return "SafetyHook error";
            case HookError::InvalidObject:
                return "Invalid object pointer";
            case HookError::VmtHookNotFound:
                return "VMT hook not found";
            case HookError::MethodAlreadyHooked:
                return "VMT method already hooked";
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
            : m_name(std::move(name)), m_type(type), m_target_address(target_address), m_status(initial_status) {}

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
        InlineHook(std::string name, uintptr_t target_address,
                   safetyhook::InlineHook hook_obj,
                   HookStatus initial_status)
            : Hook(std::move(name), HookType::Inline, target_address, initial_status),
              m_safetyhook_impl(std::move(hook_obj)) {}

        /**
         * @brief Retrieves the trampoline to call the original function.
         * @tparam T The function pointer type of the original function.
         * @return A function pointer of type T to the original function's trampoline.
         */
        template <typename T>
        T get_original() const noexcept
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
        MidHook(std::string name, uintptr_t target_address,
                safetyhook::MidHook hook_obj,
                HookStatus initial_status)
            : Hook(std::move(name), HookType::Mid, target_address, initial_status),
              m_safetyhook_impl(std::move(hook_obj)) {}

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

    /**
     * @class VmtHookEntry
     * @brief Manages a VMT hook for a single object class, wrapping SafetyHook's VmtHook.
     * @details Owns the cloned vtable and tracks individual method hooks by vtable index.
     *          VMT hooks operate at the object level by replacing the vptr with a cloned
     *          vtable. Individual methods are hooked by index within the cloned table.
     *          Does not support enable/disable toggling (SafetyHook VmHook limitation).
     */
    class VmtHookEntry
    {
    public:
        VmtHookEntry(std::string name, safetyhook::VmtHook vmt_hook)
            : m_name(std::move(name)), m_vmt_hook(std::move(vmt_hook)) {}

        const std::string &get_name() const noexcept { return m_name; }

        safetyhook::VmtHook &vmt_hook() noexcept { return m_vmt_hook; }
        const safetyhook::VmtHook &vmt_hook() const noexcept { return m_vmt_hook; }

        bool has_method_hook(size_t index) const { return m_method_hooks.find(index) != m_method_hooks.end(); }

        safetyhook::VmHook *get_method_hook(size_t index)
        {
            auto it = m_method_hooks.find(index);
            return it != m_method_hooks.end() ? &it->second : nullptr;
        }

        const safetyhook::VmHook *get_method_hook(size_t index) const
        {
            auto it = m_method_hooks.find(index);
            return it != m_method_hooks.end() ? &it->second : nullptr;
        }

        void add_method_hook(size_t index, safetyhook::VmHook hook)
        {
            m_method_hooks.emplace(index, std::move(hook));
        }

        bool remove_method_hook(size_t index)
        {
            return m_method_hooks.erase(index) > 0;
        }

        size_t method_hook_count() const noexcept { return m_method_hooks.size(); }

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
     * @class HookManager
     * @brief Manages the lifecycle of all hooks (Inline, Mid, and VMT) using SafetyHook.
     * @details Provides a centralized API for creating, removing, enabling, and disabling hooks.
     *          Thread-safe for all public methods. Uses std::expected for explicit error handling.
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
         * @details This method is safe to call during shutdown when Logger may be destroyed.
         *          It removes all hooks without attempting to log, preventing use-after-free.
         *          The shutdown flag is reset after hooks are cleared, allowing subsequent
         *          hook creation for hot-reload scenarios. The destructor becomes a no-op
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
        [[nodiscard]] std::expected<std::string, HookError> create_inline_hook(
            std::string_view name,
            uintptr_t target_address,
            void *detour_function,
            void **original_trampoline,
            const HookConfig &config = HookConfig());

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
        [[nodiscard]] std::expected<std::string, HookError> create_inline_hook_aob(
            std::string_view name,
            uintptr_t module_base,
            size_t module_size,
            std::string_view aob_pattern_str,
            ptrdiff_t aob_offset,
            void *detour_function,
            void **original_trampoline,
            const HookConfig &config = HookConfig());

        /**
         * @brief Creates a mid-function hook at a specific target memory address.
         * @param name A unique, descriptive name for the hook.
         * @param target_address The memory address within a function to hook.
         * @param detour_function The function to be called when the mid-hook is executed.
         * @param config Optional configuration settings for the hook.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         */
        [[nodiscard]] std::expected<std::string, HookError> create_mid_hook(
            std::string_view name,
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
        [[nodiscard]] std::expected<std::string, HookError> create_mid_hook_aob(
            std::string_view name,
            uintptr_t module_base,
            size_t module_size,
            std::string_view aob_pattern_str,
            ptrdiff_t aob_offset,
            safetyhook::MidHookFn detour_function,
            const HookConfig &config = HookConfig());

        /**
         * @brief Creates a VMT hook for the given object, cloning its vtable.
         * @param name A unique, descriptive name for the VMT hook.
         * @param object Pointer to the polymorphic object whose vptr will be replaced.
         * @return std::expected<std::string, HookError> The hook name if successful, error code otherwise.
         */
        [[nodiscard]] std::expected<std::string, HookError> create_vmt_hook(
            std::string_view name, void *object);

        /**
         * @brief Hooks a specific virtual method by index in a named VMT hook.
         * @tparam T The type of the destination function (function pointer or member function pointer).
         * @param vmt_name The name of the VMT hook (from create_vmt_hook).
         * @param method_index The zero-based vtable index of the method to hook.
         * @param destination The replacement function.
         * @return std::expected<size_t, HookError> The method index if successful, error code otherwise.
         */
        template <typename T>
        [[nodiscard]] std::expected<size_t, HookError> hook_vmt_method(
            std::string_view vmt_name, size_t method_index, T destination)
        {
            struct DeferredLogEntry
            {
                std::string msg;
                LogLevel level;
            };

            auto [result, deferred_logs] = [&]() -> std::pair<std::expected<size_t, HookError>, std::vector<DeferredLogEntry>>
            {
                std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

                if (m_shutdown_called.load(std::memory_order_acquire))
                {
                    return {std::unexpected(HookError::ShutdownInProgress),
                            {{std::format("HookManager: Shutdown in progress. Cannot hook VMT method on '{}'.", vmt_name), LogLevel::Error}}};
                }

                auto vmt_it = m_vmt_hooks.find(vmt_name);
                if (vmt_it == m_vmt_hooks.end())
                {
                    return {std::unexpected(HookError::VmtHookNotFound),
                            {{std::format("HookManager: VMT hook '{}' not found for method hook at index {}.", vmt_name, method_index), LogLevel::Error}}};
                }

                if (vmt_it->second.has_method_hook(method_index))
                {
                    return {std::unexpected(HookError::MethodAlreadyHooked),
                            {{std::format("HookManager: VMT '{}' method index {} is already hooked.", vmt_name, method_index), LogLevel::Error}}};
                }

                try
                {
                    auto hook_result = vmt_it->second.vmt_hook().hook_method(method_index, destination);

                    if (!hook_result)
                    {
                        return {std::unexpected(HookError::SafetyHookError),
                                {{std::format("HookManager: Failed to hook VMT '{}' method index {}.", vmt_name, method_index), LogLevel::Error}}};
                    }

                    vmt_it->second.add_method_hook(method_index, std::move(hook_result.value()));

                    return {method_index,
                            {{std::format("HookManager: Successfully hooked VMT '{}' method index {}.", vmt_name, method_index), LogLevel::Info}}};
                }
                catch (const std::exception &e)
                {
                    return {std::unexpected(HookError::UnknownError),
                            {{std::format("HookManager: Exception hooking VMT '{}' method index {}: {}", vmt_name, method_index, e.what()), LogLevel::Error}}};
                }
                catch (...)
                {
                    return {std::unexpected(HookError::UnknownError),
                            {{std::format("HookManager: Unknown exception hooking VMT '{}' method index {}.", vmt_name, method_index), LogLevel::Error}}};
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
         * @return true if found and removed, false otherwise.
         */
        [[nodiscard]] bool remove_vmt_hook(std::string_view vmt_name);

        /**
         * @brief Removes a single method hook from a VMT, restoring the original method.
         * @param vmt_name The name of the VMT hook.
         * @param method_index The vtable index of the method to unhook.
         * @return true if found and removed, false otherwise.
         */
        [[nodiscard]] bool remove_vmt_method(std::string_view vmt_name, size_t method_index);

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
                m_logger.error("HookManager: Reentrant callback detected in with_vmt_method('{}'/{})!", vmt_name, method_index);
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
                m_logger.error("HookManager: Reentrant callback detected in with_vmt_method('{}'/{})!", vmt_name, method_index);
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
         * @brief Removes a hook identified by its name.
         * @param hook_id The name of the hook to remove.
         * @return true if the hook was found and successfully removed, false otherwise.
         */
        [[nodiscard]] bool remove_hook(std::string_view hook_id);

        /**
         * @brief Removes all hooks currently managed by this HookManager instance.
         */
        void remove_all_hooks();

        /**
         * @brief Enables a previously disabled hook.
         * @param hook_id The name of the hook to enable.
         * @return true if the hook was found and successfully enabled, false otherwise.
         */
        [[nodiscard]] bool enable_hook(std::string_view hook_id);

        /**
         * @brief Disables an active hook temporarily without removing it.
         * @param hook_id The name of the hook to disable.
         * @return true if the hook was found and successfully disabled, false otherwise.
         */
        [[nodiscard]] bool disable_hook(std::string_view hook_id);

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
         * @details The callback is invoked with a reference to the InlineHook while the
         *          shared_mutex is held as a reader, preventing concurrent removal.
         * @warning DANGER: Any callback holding m_hooks_mutex must NOT call methods that
         *          acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook)
         *          because those calls will deadlock. Perform such mutations outside the callback
         *          or use an asynchronous/posted operation that does not hold m_hooks_mutex.
         * @tparam F Callable type accepting (InlineHook&) and returning a value.
         * @param hook_id The name of the inline hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value, or std::nullopt if hook not found.
         */
        template <typename F>
            requires std::invocable<F, InlineHook &> &&
                     (!std::is_void_v<std::invoke_result_t<F, InlineHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, InlineHook &>>)
        [[nodiscard]] auto with_inline_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_inline_hook('{}')! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.", hook_id);
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
            requires std::invocable<F, InlineHook &> &&
                     std::is_void_v<std::invoke_result_t<F, InlineHook &>>
        [[nodiscard]] bool with_inline_hook(std::string_view hook_id, F &&fn)
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_inline_hook('{}')! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.", hook_id);
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
         * @details Provides a non-blocking alternative to with_inline_hook(). The callback
         *          is invoked only if the lock is immediately acquired via std::try_to_lock.
         *          Note: try_to_lock only avoids blocking on initial acquisition - it does NOT
         *          make callbacks safe to re-enter HookManager methods that also acquire the
         *          same non-recursive mutex (e.g., enable_hook, disable_hook). If a callback
         *          needs to call those methods, it must release the lock first or perform those
         *          calls asynchronously to avoid deadlock. See with_inline_hook for the blocking
         *          analogue.
         * @param hook_id The name of the inline hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value. Returns std::nullopt if either
         *         the lock could not be acquired or the hook was not found.
         */
        template <typename F>
            requires std::invocable<F, InlineHook &> &&
                     (!std::is_void_v<std::invoke_result_t<F, InlineHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, InlineHook &>>)
        [[nodiscard]] auto try_with_inline_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in try_with_inline_hook('{}')! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.", hook_id);
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
         * @details The callback is invoked with a reference to the MidHook while the
         *          shared_mutex is held as a reader, preventing concurrent removal.
         * @warning DANGER: Any callback holding m_hooks_mutex must NOT call methods that
         *          acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook)
         *          because those calls will deadlock. Perform such mutations outside the callback
         *          or use an asynchronous/posted operation that does not hold m_hooks_mutex.
         * @tparam F Callable type accepting (MidHook&) and returning a value.
         * @param hook_id The name of the mid hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value, or std::nullopt if hook not found.
         */
        template <typename F>
            requires std::invocable<F, MidHook &> &&
                     (!std::is_void_v<std::invoke_result_t<F, MidHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, MidHook &>>)
        [[nodiscard]] auto with_mid_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_mid_hook('{}')! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.", hook_id);
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
            requires std::invocable<F, MidHook &> &&
                     std::is_void_v<std::invoke_result_t<F, MidHook &>>
        [[nodiscard]] bool with_mid_hook(std::string_view hook_id, F &&fn)
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in with_mid_hook('{}')! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.", hook_id);
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
         * @details Provides a non-blocking alternative to with_mid_hook(). The callback
         *          is invoked only if the lock is immediately acquired via std::try_to_lock.
         *          Note: try_to_lock only avoids blocking on initial acquisition - it does NOT
         *          make callbacks safe to re-enter HookManager methods that also acquire the
         *          same non-recursive mutex (e.g., enable_hook, disable_hook). If a callback
         *          needs to call those methods, it must release the lock first or perform those
         *          calls asynchronously to avoid deadlock. See with_mid_hook for the blocking
         *          analogue.
         * @param hook_id The name of the mid hook.
         * @param fn The callback to invoke with the hook reference.
         * @return std::optional<R> The callback's return value. Returns std::nullopt if either
         *         the lock could not be acquired or the hook was not found.
         */
        template <typename F>
            requires std::invocable<F, MidHook &> &&
                     (!std::is_void_v<std::invoke_result_t<F, MidHook &>>) &&
                     (!std::is_reference_v<std::invoke_result_t<F, MidHook &>>)
        [[nodiscard]] auto try_with_mid_hook(std::string_view hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            if (get_reentrancy_guard() > 0)
            {
                m_logger.error("HookManager: Reentrant callback detected in try_with_mid_hook('{}')! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.", hook_id);
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
        explicit HookManager(Logger &logger = Logger::get_instance());

        mutable std::shared_mutex m_hooks_mutex;
        std::unordered_map<std::string, std::unique_ptr<Hook>, TransparentStringHash, std::equal_to<>> m_hooks;
        std::unordered_map<std::string, VmtHookEntry, TransparentStringHash, std::equal_to<>> m_vmt_hooks;
        Logger &m_logger;
        std::shared_ptr<safetyhook::Allocator> m_allocator;
        std::atomic<bool> m_shutdown_called{false};

        [[nodiscard]] int &get_reentrancy_guard() noexcept
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

        std::string error_to_string(const safetyhook::InlineHook::Error &err) const;
        std::string error_to_string(const safetyhook::MidHook::Error &err) const;

        bool hook_id_exists_locked(std::string_view hook_id) const
        {
            return m_hooks.find(hook_id) != m_hooks.end();
        }

        bool vmt_hook_exists_locked(std::string_view name) const
        {
            return m_vmt_hooks.find(name) != m_vmt_hooks.end();
        }
    };
} // namespace DetourModKit

#endif // DETOURMODKIT_HOOK_MANAGER_HPP
