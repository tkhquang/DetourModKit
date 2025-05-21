#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include "safetyhook.hpp"
#include "logger.hpp"
#include "aob_scanner.hpp"
#include "string_utils.hpp"

/**
 * @enum HookType
 * @brief Enumeration of supported hook types.
 */
enum class HookType
{
    Inline, // For inline hooks (function entry point)
    Mid     // For mid-function hooks
};

/**
 * @enum HookStatus
 * @brief Represents the current status of a hook.
 */
enum class HookStatus
{
    Active,   // Hook is enabled and functioning
    Disabled, // Hook is installed but currently disabled
    Failed,   // Hook creation failed
    Removed   // Hook has been removed
};

/**
 * @struct HookConfig
 * @brief Configuration options for hook creation.
 */
struct HookConfig
{
    bool autoEnable = true; // Whether to enable the hook immediately after creation
    uint32_t flags = 0;     // SafetyHook flags
};

/**
 * @class Hook
 * @brief Base class for all hook types.
 *
 * Provides a common interface for different hook implementations.
 */
class Hook
{
public:
    /**
     * @brief Virtual destructor for proper cleanup.
     */
    virtual ~Hook() = default;

    /**
     * @brief Gets the name of the hook.
     * @return The hook's name.
     */
    std::string getName() const { return m_name; }

    /**
     * @brief Gets the type of the hook.
     * @return The hook type enum.
     */
    HookType getType() const { return m_type; }

    /**
     * @brief Gets the address that was hooked.
     * @return The target address.
     */
    uintptr_t getTargetAddress() const { return m_target_address; }

    /**
     * @brief Gets the current status of the hook.
     * @return The hook status enum.
     */
    HookStatus getStatus() const { return m_status; }

    /**
     * @brief Enables the hook if it was previously disabled.
     * @return true if the hook was successfully enabled, false otherwise.
     */
    virtual bool enable() = 0;

    /**
     * @brief Disables the hook temporarily without removing it.
     * @return true if the hook was successfully disabled, false otherwise.
     */
    virtual bool disable() = 0;

    /**
     * @brief Checks if the hook is currently enabled.
     * @return true if the hook is enabled, false otherwise.
     */
    bool isEnabled() const { return m_status == HookStatus::Active; }

protected:
    std::string m_name;         // User-friendly name for logging
    HookType m_type;            // Type of hook
    uintptr_t m_target_address; // The address that was hooked
    HookStatus m_status;        // Current status of the hook

    /**
     * @brief Protected constructor for base class.
     * @param name Name of the hook.
     * @param type Type of the hook.
     * @param target_address The address that was hooked.
     * @param initial_status Initial status of the hook.
     */
    Hook(std::string name, HookType type, uintptr_t target_address, HookStatus initial_status)
        : m_name(std::move(name)), m_type(type), m_target_address(target_address), m_status(initial_status) {}

    // Prevent copying and allow moving
    Hook(const Hook &) = delete;
    Hook &operator=(const Hook &) = delete;
    Hook(Hook &&) noexcept = default;
    Hook &operator=(Hook &&) noexcept = default;
};

/**
 * @class InlineHook
 * @brief Implementation of Hook for SafetyHook InlineHook.
 */
class InlineHook : public Hook
{
public:
    /**
     * @brief Constructor for InlineHook.
     * @param name Name of the hook.
     * @param target_address The address that was hooked.
     * @param hook_obj The SafetyHook InlineHook object.
     * @param initial_status Initial status of the hook.
     */
    InlineHook(std::string name, uintptr_t target_address,
               std::unique_ptr<safetyhook::InlineHook> hook_obj,
               HookStatus initial_status)
        : Hook(std::move(name), HookType::Inline, target_address, initial_status),
          m_hook_obj(std::move(hook_obj)) {}

    /**
     * @brief Enables the hook.
     * @return true if successful, false otherwise.
     */
    bool enable() override
    {
        if (m_status != HookStatus::Disabled || !m_hook_obj)
        {
            return false;
        }

        auto result = m_hook_obj->enable();
        if (result)
        {
            m_status = HookStatus::Active;
            return true;
        }
        return false;
    }

    /**
     * @brief Disables the hook.
     * @return true if successful, false otherwise.
     */
    bool disable() override
    {
        if (m_status != HookStatus::Active || !m_hook_obj)
        {
            return false;
        }

        auto result = m_hook_obj->disable();
        if (result)
        {
            m_status = HookStatus::Disabled;
            return true;
        }
        return false;
    }

    /**
     * @brief Gets the original function trampoline.
     * @tparam T Type of the function pointer.
     * @return The original function trampoline.
     */
    template <typename T>
    T getOriginal() const
    {
        return m_hook_obj ? m_hook_obj->original<T>() : nullptr;
    }

private:
    std::unique_ptr<safetyhook::InlineHook> m_hook_obj; // The SafetyHook InlineHook object
};

/**
 * @class MidHook
 * @brief Implementation of Hook for SafetyHook MidHook.
 */
class MidHook : public Hook
{
public:
    /**
     * @brief Constructor for MidHook.
     * @param name Name of the hook.
     * @param target_address The address that was hooked.
     * @param hook_obj The SafetyHook MidHook object.
     * @param initial_status Initial status of the hook.
     */
    MidHook(std::string name, uintptr_t target_address,
            std::unique_ptr<safetyhook::MidHook> hook_obj,
            HookStatus initial_status)
        : Hook(std::move(name), HookType::Mid, target_address, initial_status),
          m_hook_obj(std::move(hook_obj)) {}

    /**
     * @brief Enables the hook.
     * @return true if successful, false otherwise.
     */
    bool enable() override
    {
        if (m_status != HookStatus::Disabled || !m_hook_obj)
        {
            return false;
        }

        auto result = m_hook_obj->enable();
        if (result)
        {
            m_status = HookStatus::Active;
            return true;
        }
        return false;
    }

    /**
     * @brief Disables the hook.
     * @return true if successful, false otherwise.
     */
    bool disable() override
    {
        if (m_status != HookStatus::Active || !m_hook_obj)
        {
            return false;
        }

        auto result = m_hook_obj->disable();
        if (result)
        {
            m_status = HookStatus::Disabled;
            return true;
        }
        return false;
    }

    /**
     * @brief Gets the destination function.
     * @return The destination function.
     */
    safetyhook::MidHookFn getDestination() const
    {
        return m_hook_obj ? m_hook_obj->destination() : nullptr;
    }

private:
    std::unique_ptr<safetyhook::MidHook> m_hook_obj; // The SafetyHook MidHook object
};

/**
 * @class HookManager
 * @brief Manages the lifecycle of all SafetyHook hooks.
 *
 * Provides a centralized way to create, enable, disable, and remove hooks.
 * Can be used as a singleton or instantiated directly.
 */
class HookManager
{
public:
    /**
     * @brief Singleton access pattern.
     * @return Reference to the global HookManager instance.
     */
    static HookManager &getInstance();

    /**
     * @brief Constructor for HookManager.
     * @param logger Optional pointer to logger. If null, uses Logger singleton.
     */
    explicit HookManager(Logger *logger = nullptr);

    /**
     * @brief Destructor. Cleans up all hooks.
     */
    ~HookManager();

    // --- Inline Hook Creation ---
    /**
     * @brief Creates an inline hook at the specified address.
     * @param name A descriptive name for the hook (for logging).
     * @param target_address The address to hook.
     * @param detour_function The function to call instead of the original.
     * @param original_trampoline Pointer to store the trampoline for calling the original function.
     * @param config Optional configuration for the hook.
     * @return A unique ID for the hook if successful, or an empty string on failure.
     */
    std::string create_inline_hook(
        const std::string &name,
        uintptr_t target_address,
        void *detour_function,
        void **original_trampoline,
        const HookConfig &config = HookConfig());

    /**
     * @brief Creates an inline hook by first finding the target address using AOB scanning.
     * @param name A descriptive name for the hook.
     * @param module_base Base address of the module to scan.
     * @param module_size Size of the module to scan.
     * @param aob_pattern The AOB pattern string to find the target.
     * @param aob_offset An optional offset to add to the AOB match to get the final target_address.
     * @param detour_function The function to call instead of the original.
     * @param original_trampoline Pointer to store the trampoline for calling the original function.
     * @param config Optional configuration for the hook.
     * @return A unique ID for the hook if successful, or an empty string on failure.
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

    // --- Mid Hook Creation ---
    /**
     * @brief Creates a mid-function hook at the specified address.
     * @param name A descriptive name for the hook (for logging).
     * @param target_address The address to hook.
     * @param detour_function The function to call at the hook point.
     * @param config Optional configuration for the hook.
     * @return A unique ID for the hook if successful, or an empty string on failure.
     */
    std::string create_mid_hook(
        const std::string &name,
        uintptr_t target_address,
        safetyhook::MidHookFn detour_function,
        const HookConfig &config = HookConfig());

    /**
     * @brief Creates a mid-function hook by first finding the target address using AOB scanning.
     * @param name A descriptive name for the hook.
     * @param module_base Base address of the module to scan.
     * @param module_size Size of the module to scan.
     * @param aob_pattern The AOB pattern string to find the target.
     * @param aob_offset An optional offset to add to the AOB match to get the final target_address.
     * @param detour_function The function to call at the hook point.
     * @param config Optional configuration for the hook.
     * @return A unique ID for the hook if successful, or an empty string on failure.
     */
    std::string create_mid_hook_aob(
        const std::string &name,
        uintptr_t module_base,
        size_t module_size,
        const std::string &aob_pattern_str,
        ptrdiff_t aob_offset,
        safetyhook::MidHookFn detour_function,
        const HookConfig &config = HookConfig());

    // --- Hook Management ---
    /**
     * @brief Removes a hook by its ID.
     * @param hook_id The ID of the hook to remove.
     * @return true if the hook was found and removed, false otherwise.
     */
    bool remove_hook(const std::string &hook_id);

    /**
     * @brief Removes all managed hooks.
     */
    void remove_all_hooks();

    /**
     * @brief Enables a hook by its ID.
     * @param hook_id The ID of the hook to enable.
     * @return true if the hook was found and enabled, false otherwise.
     */
    bool enable_hook(const std::string &hook_id);

    /**
     * @brief Disables a hook by its ID.
     * @param hook_id The ID of the hook to disable.
     * @return true if the hook was found and disabled, false otherwise.
     */
    bool disable_hook(const std::string &hook_id);

    /**
     * @brief Gets the status of a hook by its ID.
     * @param hook_id The ID of the hook to check.
     * @return The status of the hook, or HookStatus::Removed if not found.
     */
    HookStatus get_hook_status(const std::string &hook_id) const;

    /**
     * @brief Gets a count of hooks by status.
     * @return A map of HookStatus to count.
     */
    std::unordered_map<HookStatus, size_t> get_hook_counts() const;

    /**
     * @brief Gets a list of hook IDs.
     * @param status_filter Optional filter for specific hook status.
     * @return A vector of hook IDs.
     */
    std::vector<std::string> get_hook_ids(HookStatus status_filter = HookStatus::Active) const;

    /**
     * @brief Gets a hook by its ID.
     * @param hook_id The ID of the hook to retrieve.
     * @return A pointer to the hook or nullptr if not found.
     */
    Hook *get_hook(const std::string &hook_id);

    /**
     * @brief Gets an inline hook by its ID.
     * @param hook_id The ID of the hook to retrieve.
     * @return A pointer to the inline hook or nullptr if not found or wrong type.
     */
    InlineHook *get_inline_hook(const std::string &hook_id);

    /**
     * @brief Gets a mid hook by its ID.
     * @param hook_id The ID of the hook to retrieve.
     * @return A pointer to the mid hook or nullptr if not found or wrong type.
     */
    MidHook *get_mid_hook(const std::string &hook_id);

private:
    // Delete copy/assignment
    HookManager(const HookManager &) = delete;
    HookManager &operator=(const HookManager &) = delete;

    // Allow moving
    HookManager(HookManager &&) noexcept = default;
    HookManager &operator=(HookManager &&) noexcept = default;

    // Member variables
    mutable std::recursive_mutex m_hooks_mutex;
    std::vector<std::unique_ptr<Hook>> m_hooks;         // Stores all active hooks
    Logger *m_logger;                                   // Pointer to the logger
    std::shared_ptr<safetyhook::Allocator> m_allocator; // Allocator for SafetyHook

    // Helper methods
    std::string error_to_string(const safetyhook::InlineHook::Error &err) const;
    std::string error_to_string(const safetyhook::MidHook::Error &err) const;

    /**
     * @brief Finds a hook by its ID.
     * @param hook_id The ID of the hook to find.
     * @return Iterator to the hook or m_hooks.end() if not found.
     */
    auto find_hook(const std::string &hook_id) -> decltype(m_hooks.begin());

    /**
     * @brief Finds a hook by its ID (const version).
     * @param hook_id The ID of the hook to find.
     * @return Const iterator to the hook or m_hooks.end() if not found.
     */
    auto find_hook(const std::string &hook_id) const -> decltype(m_hooks.cbegin());

    /**
     * @brief Checks if a hook ID already exists.
     * @param hook_id The ID to check.
     * @return true if the ID exists, false otherwise.
     */
    bool hook_id_exists(const std::string &hook_id) const;
};

#endif // HOOK_MANAGER_H
