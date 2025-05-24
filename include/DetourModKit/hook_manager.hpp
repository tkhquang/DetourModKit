#ifndef HOOK_MANAGER_HPP
#define HOOK_MANAGER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

#include "safetyhook.hpp"
#include "logger.hpp"
#include "aob_scanner.hpp"
#include "string_utils.hpp"

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
     * @struct HookConfig
     * @brief Configuration options used during the creation of a new hook.
     */
    struct HookConfig
    {
        bool autoEnable = true;
        uint32_t flags = 0;
    };

    /**
     * @class Hook
     * @brief Abstract base class for managed hooks.
     * @details Defines a common interface for interacting with different types of hooks
     *          managed by the HookManager.
     */
    class Hook
    {
    public:
        virtual ~Hook() = default;

        const std::string &getName() const { return m_name; }
        HookType getType() const { return m_type; }
        uintptr_t getTargetAddress() const { return m_target_address; }
        HookStatus getStatus() const { return m_status; }

        /**
         * @brief Pure virtual function to enable the hook.
         * @return true if the hook was successfully enabled, false otherwise.
         */
        virtual bool enable() = 0;

        /**
         * @brief Pure virtual function to disable the hook.
         * @return true if the hook was successfully disabled, false otherwise.
         */
        virtual bool disable() = 0;

        bool isEnabled() const { return m_status == HookStatus::Active; }

        static std::string statusToString(HookStatus status)
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

    protected:
        std::string m_name;
        HookType m_type;
        uintptr_t m_target_address;
        HookStatus m_status;

        Hook(std::string name, HookType type, uintptr_t target_address, HookStatus initial_status)
            : m_name(std::move(name)), m_type(type), m_target_address(target_address), m_status(initial_status) {}

        Hook(const Hook &) = delete;
        Hook &operator=(const Hook &) = delete;
        Hook(Hook &&) noexcept = default;
        Hook &operator=(Hook &&) noexcept = default;
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

        bool enable() override
        {
            if (!m_safetyhook_impl)
                return false;
            if (m_status == HookStatus::Active)
                return true;
            if (m_status != HookStatus::Disabled)
                return false;

            auto result = m_safetyhook_impl->enable();
            if (result)
            {
                m_status = HookStatus::Active;
                return true;
            }
            return false;
        }

        bool disable() override
        {
            if (!m_safetyhook_impl)
                return false;
            if (m_status == HookStatus::Disabled)
                return true;
            if (m_status != HookStatus::Active)
                return false;

            auto result = m_safetyhook_impl->disable();
            if (result)
            {
                m_status = HookStatus::Disabled;
                return true;
            }
            return false;
        }

        /**
         * @brief Retrieves the trampoline to call the original function.
         * @tparam T The function pointer type of the original function.
         * @return A function pointer of type T to the original function's trampoline.
         */
        template <typename T>
        T getOriginal() const
        {
            return m_safetyhook_impl ? m_safetyhook_impl->original<T>() : nullptr;
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

        bool enable() override
        {
            if (!m_safetyhook_impl)
                return false;
            if (m_status == HookStatus::Active)
                return true;
            if (m_status != HookStatus::Disabled)
                return false;

            auto result = m_safetyhook_impl->enable();
            if (result)
            {
                m_status = HookStatus::Active;
                return true;
            }
            return false;
        }

        bool disable() override
        {
            if (!m_safetyhook_impl)
                return false;
            if (m_status == HookStatus::Disabled)
                return true;
            if (m_status != HookStatus::Active)
                return false;

            auto result = m_safetyhook_impl->disable();
            if (result)
            {
                m_status = HookStatus::Disabled;
                return true;
            }
            return false;
        }

        /**
         * @brief Gets the destination function of this mid-hook.
         * @return safetyhook::MidHookFn The function pointer to the detour.
         */
        safetyhook::MidHookFn getDestination() const
        {
            return m_safetyhook_impl ? m_safetyhook_impl->destination() : nullptr;
        }

    private:
        std::unique_ptr<safetyhook::MidHook> m_safetyhook_impl;
    };

    /**
     * @class HookManager
     * @brief Manages the lifecycle of all hooks (Inline and Mid) using SafetyHook.
     * @details Provides a centralized API for creating, removing, enabling, and disabling hooks.
     *          Thread-safe for all public methods.
     */
    class HookManager
    {
    public:
        /**
         * @brief Provides access to the singleton instance of the HookManager.
         * @return HookManager& Reference to the global HookManager instance.
         */
        static HookManager &getInstance();

        explicit HookManager(Logger *logger = nullptr);
        ~HookManager();

        /**
         * @brief Creates an inline hook at a specific target memory address.
         * @param name A unique, descriptive name for the hook.
         * @param target_address The memory address of the function to hook.
         * @param detour_function Pointer to the detour function.
         * @param original_trampoline Output pointer to receive trampoline address.
         * @param config Optional configuration settings for the hook.
         * @return std::string The hook name if successful, empty string otherwise.
         */
        std::string create_inline_hook(
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
         * @return std::string The hook name if successful, empty string otherwise.
         */
        std::string create_inline_hook_aob(
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
         * @return std::string The hook name if successful, empty string otherwise.
         */
        std::string create_mid_hook(
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
         * @return std::string The hook name if successful, empty string otherwise.
         */
        std::string create_mid_hook_aob(
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
        bool enable_hook(const std::string &hook_id);

        /**
         * @brief Disables an active hook temporarily without removing it.
         * @param hook_id The name of the hook to disable.
         * @return true if the hook was found and successfully disabled, false otherwise.
         */
        bool disable_hook(const std::string &hook_id);

        /**
         * @brief Retrieves the current status of a hook.
         * @param hook_id The name of the hook.
         * @return HookStatus The current status or HookStatus::Removed if not found.
         */
        HookStatus get_hook_status(const std::string &hook_id) const;

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
         * @brief Retrieves a pointer to an InlineHook object by its ID.
         * @param hook_id The name of the inline hook.
         * @return InlineHook* Pointer to the InlineHook object if found, nullptr otherwise.
         */
        InlineHook *get_inline_hook(const std::string &hook_id);

        /**
         * @brief Retrieves a pointer to a MidHook object by its ID.
         * @param hook_id The name of the mid hook.
         * @return MidHook* Pointer to the MidHook object if found, nullptr otherwise.
         */
        MidHook *get_mid_hook(const std::string &hook_id);

    private:
        HookManager(const HookManager &) = delete;
        HookManager &operator=(const HookManager &) = delete;
        HookManager(HookManager &&) noexcept = default;
        HookManager &operator=(HookManager &&) noexcept = default;

        mutable std::recursive_mutex m_hooks_mutex;
        std::vector<std::unique_ptr<Hook>> m_hooks;
        Logger *m_logger;
        std::shared_ptr<safetyhook::Allocator> m_allocator;

        std::string error_to_string(const safetyhook::InlineHook::Error &err) const;
        std::string error_to_string(const safetyhook::MidHook::Error &err) const;

        auto find_hook_iterator(const std::string &hook_id) -> decltype(m_hooks.begin());
        auto find_hook_iterator(const std::string &hook_id) const -> decltype(m_hooks.cbegin());

        bool hook_id_exists(const std::string &hook_id) const;
        Hook *get_hook_raw_ptr(const std::string &hook_id);
    };
} // namespace DetourModKit

#endif // HOOK_MANAGER_HPP
