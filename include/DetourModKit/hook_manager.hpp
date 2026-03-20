#ifndef HOOK_MANAGER_HPP
#define HOOK_MANAGER_HPP

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
#include <cassert>
#include <utility>

#include "safetyhook.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/scanner.hpp"
#include "DetourModKit/format.hpp"

namespace DetourModKit
{
    /**
     * @enum HookType
     * @brief Enumeration of supported hook types, corresponding to SafetyHook capabilities.
     */
    enum class HookType
    {
        Inline,
        Mid
    };

    /**
     * @enum HookStatus
     * @brief Represents the current operational status of a managed hook.
     */
    enum class HookStatus
    {
        Active,
        Disabled,
        Failed,
        Removed
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
        SafetyHookError,
        UnknownError
    };

    /**
     * @struct HookConfig
     * @brief Configuration options used during the creation of a new hook.
     */
    struct HookConfig
    {
        bool auto_enable = true;
        safetyhook::InlineHook::Flags inline_flags = static_cast<safetyhook::InlineHook::Flags>(0);
        safetyhook::MidHook::Flags mid_flags = static_cast<safetyhook::MidHook::Flags>(0);
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
        HookStatus get_status() const noexcept { return m_status; }

        /**
         * @brief Enables the hook.
         * @return true if the hook was successfully enabled, false otherwise.
         * @note This is a Template Method; derived classes implement do_enable().
         */
        bool enable()
        {
            if (!is_impl_valid())
                return false;
            if (m_status == HookStatus::Active)
                return true;
            if (m_status != HookStatus::Disabled)
                return false;

            if (do_enable())
            {
                m_status = HookStatus::Active;
                return true;
            }
            return false;
        }

        /**
         * @brief Disables the hook.
         * @return true if the hook was successfully disabled, false otherwise.
         * @note This is a Template Method; derived classes implement do_disable().
         */
        bool disable()
        {
            if (!is_impl_valid())
                return false;
            if (m_status == HookStatus::Disabled)
                return true;
            if (m_status != HookStatus::Active)
                return false;

            if (do_disable())
            {
                m_status = HookStatus::Disabled;
                return true;
            }
            return false;
        }

        bool is_enabled() const noexcept { return m_status == HookStatus::Active; }

        static std::string_view status_to_string(HookStatus status)
        {
            switch (status)
            {
            case HookStatus::Active:
                return "Active";
            case HookStatus::Disabled:
                return "Disabled";
            case HookStatus::Failed:
                return "Failed";
            case HookStatus::Removed:
                return "Removed";
            default:
                return "Unknown";
            }
        }

        static std::string_view error_to_string(HookError error)
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
            case HookError::SafetyHookError:
                return "SafetyHook error";
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
        HookStatus m_status;

        Hook(std::string name, HookType type, uintptr_t target_address, HookStatus initial_status)
            : m_name(std::move(name)), m_type(type), m_target_address(target_address), m_status(initial_status) {}

        virtual bool is_impl_valid() const noexcept = 0;
        virtual bool do_enable() = 0;
        virtual bool do_disable() = 0;

        Hook(const Hook &) = delete;
        Hook &operator=(const Hook &) = delete;
    };

    /**
     * @class InlineHook
     * @brief Represents a managed inline hook, wrapping a SafetyHook::InlineHook object.
     */
    class InlineHook : public Hook
    {
    public:
        InlineHook(std::string name, uintptr_t target_address,
                   std::unique_ptr<safetyhook::InlineHook> hook_obj,
                   HookStatus initial_status)
            : Hook(std::move(name), HookType::Inline, target_address, initial_status),
              m_safetyhook_impl(std::move(hook_obj)) {}

        /**
         * @brief Retrieves the trampoline to call the original function.
         * @tparam T The function pointer type of the original function.
         * @return A function pointer of type T to the original function's trampoline.
         */
        template <typename T>
        T get_original() const
        {
            return m_safetyhook_impl ? m_safetyhook_impl->original<T>() : nullptr;
        }

    protected:
        bool is_impl_valid() const noexcept override { return m_safetyhook_impl != nullptr; }
        bool do_enable() override
        {
            auto result = m_safetyhook_impl->enable();
            return result.has_value();
        }
        bool do_disable() override
        {
            auto result = m_safetyhook_impl->disable();
            return result.has_value();
        }

    private:
        std::unique_ptr<safetyhook::InlineHook> m_safetyhook_impl;
    };

    /**
     * @class MidHook
     * @brief Represents a managed mid-function hook, wrapping a SafetyHook::MidHook object.
     */
    class MidHook : public Hook
    {
    public:
        MidHook(std::string name, uintptr_t target_address,
                std::unique_ptr<safetyhook::MidHook> hook_obj,
                HookStatus initial_status)
            : Hook(std::move(name), HookType::Mid, target_address, initial_status),
              m_safetyhook_impl(std::move(hook_obj)) {}

        /**
         * @brief Gets the destination function of this mid-hook.
         * @return safetyhook::MidHookFn The function pointer to the detour.
         */
        safetyhook::MidHookFn get_destination() const
        {
            return m_safetyhook_impl ? m_safetyhook_impl->destination() : nullptr;
        }

    protected:
        bool is_impl_valid() const noexcept override { return m_safetyhook_impl != nullptr; }
        bool do_enable() override
        {
            auto result = m_safetyhook_impl->enable();
            return result.has_value();
        }
        bool do_disable() override
        {
            auto result = m_safetyhook_impl->disable();
            return result.has_value();
        }

    private:
        std::unique_ptr<safetyhook::MidHook> m_safetyhook_impl;
    };

    /**
     * @class HookManager
     * @brief Manages the lifecycle of all hooks (Inline and Mid) using SafetyHook.
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

        explicit HookManager(Logger &logger = Logger::get_instance());
        ~HookManager();

        /**
         * @brief Explicitly shuts down the HookManager, removing all hooks without logging.
         * @details This method is safe to call during shutdown when Logger may be destroyed.
         *          It removes all hooks without attempting to log, preventing use-after-free.
         *          After calling shutdown(), the destructor becomes a no-op.
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
            const std::string &name,
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
            const std::string &name,
            uintptr_t module_base,
            size_t module_size,
            const std::string &aob_pattern_str,
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
            const std::string &name,
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
            const std::string &name,
            uintptr_t module_base,
            size_t module_size,
            const std::string &aob_pattern_str,
            ptrdiff_t aob_offset,
            safetyhook::MidHookFn detour_function,
            const HookConfig &config = HookConfig());

        /**
         * @brief Removes a hook identified by its name.
         * @param hook_id The name of the hook to remove.
         * @return true if the hook was found and successfully removed, false otherwise.
         */
        bool remove_hook(const std::string &hook_id);

        /**
         * @brief Removes all hooks currently managed by this HookManager instance.
         */
        void remove_all_hooks();

        /**
         * @brief Enables a previously disabled hook.
         * @param hook_id The name of the hook to enable.
         * @return true if the hook was found and successfully enabled, false otherwise.
         */
        [[nodiscard]] bool enable_hook(const std::string &hook_id);

        /**
         * @brief Disables an active hook temporarily without removing it.
         * @param hook_id The name of the hook to disable.
         * @return true if the hook was found and successfully disabled, false otherwise.
         */
        [[nodiscard]] bool disable_hook(const std::string &hook_id);

        /**
         * @brief Retrieves the current status of a hook.
         * @param hook_id The name of the hook.
         * @return std::optional<HookStatus> The current status, or std::nullopt if not found.
         */
        std::optional<HookStatus> get_hook_status(const std::string &hook_id) const;

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
        [[nodiscard]] auto with_inline_hook(const std::string &hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            assert(!m_callback_reentrancy_guard && "HookManager: Reentrant callback detected! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.");
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
            ++m_callback_reentrancy_guard;
            struct Guard
            {
                int &counter;
                ~Guard() noexcept { --counter; }
            } guard{m_callback_reentrancy_guard};
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Inline)
            {
                return fn(static_cast<InlineHook &>(*it->second));
            }
            return std::nullopt;
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
        [[nodiscard]] auto try_with_inline_hook(const std::string &hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, InlineHook &>>
        {
            assert(!m_callback_reentrancy_guard && "HookManager: Reentrant callback detected! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.");
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex, std::try_to_lock);
            if (!lock.owns_lock())
            {
                return std::nullopt;
            }
            ++m_callback_reentrancy_guard;
            struct Guard
            {
                int &counter;
                ~Guard() noexcept { --counter; }
            } guard{m_callback_reentrancy_guard};
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Inline)
            {
                return fn(static_cast<InlineHook &>(*it->second));
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
        [[nodiscard]] auto with_mid_hook(const std::string &hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            assert(!m_callback_reentrancy_guard && "HookManager: Reentrant callback detected! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.");
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
            ++m_callback_reentrancy_guard;
            struct Guard
            {
                int &counter;
                ~Guard() noexcept { --counter; }
            } guard{m_callback_reentrancy_guard};
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Mid)
            {
                return fn(static_cast<MidHook &>(*it->second));
            }
            return std::nullopt;
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
        [[nodiscard]] auto try_with_mid_hook(const std::string &hook_id, F &&fn)
            -> std::optional<std::invoke_result_t<F, MidHook &>>
        {
            assert(!m_callback_reentrancy_guard && "HookManager: Reentrant callback detected! Callback holding m_hooks_mutex must not call HookManager methods that acquire a unique_lock (remove_hook, enable_hook, disable_hook, create_*_hook). Perform mutations outside the callback or use an asynchronous operation.");
            std::shared_lock<std::shared_mutex> lock(m_hooks_mutex, std::try_to_lock);
            if (!lock.owns_lock())
            {
                return std::nullopt;
            }
            ++m_callback_reentrancy_guard;
            struct Guard
            {
                int &counter;
                ~Guard() noexcept { --counter; }
            } guard{m_callback_reentrancy_guard};
            auto it = m_hooks.find(hook_id);
            if (it != m_hooks.end() && it->second->get_type() == HookType::Mid)
            {
                return fn(static_cast<MidHook &>(*it->second));
            }
            return std::nullopt;
        }

    private:
        mutable std::shared_mutex m_hooks_mutex;
        std::unordered_map<std::string, std::unique_ptr<Hook>> m_hooks;
        Logger &m_logger;
        std::shared_ptr<safetyhook::Allocator> m_allocator;
        std::atomic<bool> m_shutdown_called{false};
        int m_callback_reentrancy_guard{0};

        std::string error_to_string(const safetyhook::InlineHook::Error &err) const;
        std::string error_to_string(const safetyhook::MidHook::Error &err) const;

        // Non-locking variants - caller must already hold m_hooks_mutex
        bool hook_id_exists_locked(const std::string &hook_id) const;
        Hook *get_hook_raw_ptr_locked(const std::string &hook_id);
    };
} // namespace DetourModKit

#endif // HOOK_MANAGER_HPP
