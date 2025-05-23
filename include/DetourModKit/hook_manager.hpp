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

/**
 * @enum HookType
 * @brief Enumeration of supported hook types, corresponding to SafetyHook capabilities.
 */
enum class HookType
{
    Inline, /**< Represents a standard inline hook placed at the beginning of a function. */
    Mid     /**< Represents a mid-function hook, allowing redirection from within a function's body. */
};

/**
 * @enum HookStatus
 * @brief Represents the current operational status of a managed hook.
 */
enum class HookStatus
{
    Active,   /**< Hook is currently installed and enabled; the detour is active. */
    Disabled, /**< Hook is installed but currently disabled; execution flows through original code. */
    Failed,   /**< Hook creation or a critical operation failed. This status is less common for active hooks
                   as failed creations typically prevent them from being added to manager. */
    Removed   /**< Hook has been removed or was never successfully created/found. */
};

/**
 * @struct HookConfig
 * @brief Configuration options used during the creation of a new hook.
 */
struct HookConfig
{
    bool autoEnable = true; /**< If true, the hook will be enabled immediately after successful creation.
                                 If false, it will be created in a disabled state. Defaults to true. */
    uint32_t flags = 0;     /**< Additional flags to pass to the underlying SafetyHook creation functions.
                                 Allows fine-grained control over hook behavior (e.g., safetyhook::InlineHook::StartDisabled). */
};

/**
 * @class Hook
 * @brief Abstract base class for managed hooks.
 *
 * Defines a common interface for interacting with different types of hooks
 * (e.g., InlineHook, MidHook) managed by the HookManager. It standardizes
 * operations like enabling, disabling, and querying status.
 */
class Hook
{
public:
    /**
     * @brief Virtual destructor. Ensures proper cleanup of derived hook types.
     */
    virtual ~Hook() = default;

    /**
     * @brief Retrieves the user-defined name of the hook.
     * @return const std::string& The name of the hook.
     */
    const std::string &getName() const { return m_name; }

    /**
     * @brief Retrieves the type of the hook (e.g., Inline or Mid).
     * @return HookType The type of this hook.
     */
    HookType getType() const { return m_type; }

    /**
     * @brief Retrieves the memory address that this hook targets.
     * @return uintptr_t The target memory address.
     */
    uintptr_t getTargetAddress() const { return m_target_address; }

    /**
     * @brief Retrieves the current operational status of the hook.
     * @return HookStatus The current status (e.g., Active, Disabled).
     */
    HookStatus getStatus() const { return m_status; }

    /**
     * @brief Pure virtual function to enable the hook.
     * @details Derived classes must implement this to activate their specific hook type.
     * @return true if the hook was successfully enabled, false otherwise (e.g., if already active or an error occurs).
     */
    virtual bool enable() = 0;

    /**
     * @brief Pure virtual function to disable the hook.
     * @details Derived classes must implement this to deactivate their specific hook type temporarily.
     * @return true if the hook was successfully disabled, false otherwise (e.g., if already disabled or an error occurs).
     */
    virtual bool disable() = 0;

    /**
     * @brief Checks if the hook is currently active (enabled).
     * @return true if the hook's status is Active, false otherwise.
     */
    bool isEnabled() const { return m_status == HookStatus::Active; }

    /**
     * @brief Converts HookStatus enum to its string representation.
     * @param status The HookStatus enum value.
     * @return std::string String representation of the status.
     */
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
    std::string m_name;         /**< User-friendly name for identification and logging. */
    HookType m_type;            /**< The type of this hook (Inline or Mid). */
    uintptr_t m_target_address; /**< The memory address targeted by this hook. */
    HookStatus m_status;        /**< The current operational status of this hook. */

    /**
     * @brief Protected constructor for derived hook classes.
     * @param name User-defined name for the hook.
     * @param type The type of hook being created.
     * @param target_address The memory address to be hooked.
     * @param initial_status The initial status for the hook upon creation.
     */
    Hook(std::string name, HookType type, uintptr_t target_address, HookStatus initial_status)
        : m_name(std::move(name)), m_type(type), m_target_address(target_address), m_status(initial_status) {}

    // Prevent copying of Hook objects, allow moving.
    Hook(const Hook &) = delete;
    Hook &operator=(const Hook &) = delete;
    Hook(Hook &&) noexcept = default;            // Default move constructor
    Hook &operator=(Hook &&) noexcept = default; // Default move assignment
};

/**
 * @class InlineHook
 * @brief Represents a managed inline hook, wrapping a SafetyHook::InlineHook object.
 */
class InlineHook : public Hook
{
public:
    /**
     * @brief Constructs an InlineHook object.
     * @param name User-defined name for the hook.
     * @param target_address The memory address to hook.
     * @param hook_obj A std::unique_ptr to a SafetyHook::InlineHook object that implements the low-level hook.
     * @param initial_status The initial operational status of this hook.
     */
    InlineHook(std::string name, uintptr_t target_address,
               std::unique_ptr<safetyhook::InlineHook> hook_obj,
               HookStatus initial_status)
        : Hook(std::move(name), HookType::Inline, target_address, initial_status),
          m_safetyhook_impl(std::move(hook_obj)) {}

    /**
     * @brief Enables this inline hook.
     * @return true if successfully enabled or already active, false on failure or if hook object is invalid.
     */
    bool enable() override
    {
        if (!m_safetyhook_impl)
            return false; // Hook object is not valid
        if (m_status == HookStatus::Active)
            return true; // Already active
        if (m_status != HookStatus::Disabled)
            return false; // Can only enable if currently disabled

        auto result = m_safetyhook_impl->enable();
        if (result) // SafetyHook's enable returns an expected<void, Error> or similar
        {
            m_status = HookStatus::Active;
            return true;
        }
        // Log error from result.error() if needed by HookManager
        return false;
    }

    /**
     * @brief Disables this inline hook.
     * @return true if successfully disabled or already disabled, false on failure or if hook object is invalid.
     */
    bool disable() override
    {
        if (!m_safetyhook_impl)
            return false; // Hook object is not valid
        if (m_status == HookStatus::Disabled)
            return true; // Already disabled
        if (m_status != HookStatus::Active)
            return false; // Can only disable if currently active

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
     *         Returns nullptr if the underlying SafetyHook object is invalid.
     */
    template <typename T>
    T getOriginal() const
    {
        return m_safetyhook_impl ? m_safetyhook_impl->original<T>() : nullptr;
    }

private:
    std::unique_ptr<safetyhook::InlineHook> m_safetyhook_impl; /**< Pointer to the SafetyHook implementation. */
};

/**
 * @class MidHook
 * @brief Represents a managed mid-function hook, wrapping a SafetyHook::MidHook object.
 */
class MidHook : public Hook
{
public:
    /**
     * @brief Constructs a MidHook object.
     * @param name User-defined name for the hook.
     * @param target_address The memory address within a function to hook.
     * @param hook_obj A std::unique_ptr to a SafetyHook::MidHook object.
     * @param initial_status The initial operational status of this hook.
     */
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
     * @details This is the function that SafetyHook calls when the mid-hook is triggered.
     * @return safetyhook::MidHookFn The function pointer to the detour.
     *         Returns nullptr if the underlying SafetyHook object is invalid.
     */
    safetyhook::MidHookFn getDestination() const
    {
        return m_safetyhook_impl ? m_safetyhook_impl->destination() : nullptr;
    }

private:
    std::unique_ptr<safetyhook::MidHook> m_safetyhook_impl; /**< Pointer to the SafetyHook implementation. */
};

/**
 * @class HookManager
 * @brief Manages the lifecycle of all hooks (Inline and Mid) using SafetyHook.
 *
 * Provides a centralized API for creating, removing, enabling, and disabling hooks.
 * It can be used as a singleton via `getInstance()` or instantiated directly if multiple
 * independent hook managers are needed (though singleton usage is more common).
 * This class is thread-safe for its public methods.
 */
class HookManager
{
public:
    /**
     * @brief Provides access to the singleton instance of the HookManager.
     * @return HookManager& Reference to the global HookManager instance.
     */
    static HookManager &getInstance();

    /**
     * @brief Constructs a HookManager.
     * @param logger Optional. A pointer to a Logger instance to use. If nullptr,
     *               `Logger::getInstance()` will be used.
     */
    explicit HookManager(Logger *logger = nullptr);

    /**
     * @brief Destructor. Ensures all managed hooks are removed and resources are cleaned up.
     */
    ~HookManager();

    // --- Inline Hook Creation Methods ---
    /**
     * @brief Creates an inline hook at a specific target memory address.
     * @param name A unique, descriptive name for the hook (used as its ID).
     * @param target_address The memory address of the function to hook.
     * @param detour_function Pointer to the detour function that will replace the original.
     * @param original_trampoline Output. Pointer to a `void*` that will receive the address
     *                            of the trampoline function (to call the original function).
     * @param config Optional. Configuration settings for the hook (e.g., auto-enable, flags).
     * @return std::string The `name` of the hook if creation was successful, otherwise an empty string.
     */
    std::string create_inline_hook(
        const std::string &name,
        uintptr_t target_address,
        void *detour_function,
        void **original_trampoline,
        const HookConfig &config = HookConfig());

    /**
     * @brief Creates an inline hook by first finding the target address via an AOB (Array-of-Bytes) scan.
     * @param name A unique, descriptive name for the hook (used as its ID).
     * @param module_base Base address of the memory module/region to scan.
     * @param module_size Size of the memory module/region to scan.
     * @param aob_pattern_str The AOB pattern string (e.g., "48 8B ?? C1").
     * @param aob_offset Offset to add to the found pattern's address to get the final hook target.
     * @param detour_function Pointer to the detour function.
     * @param original_trampoline Output. Pointer to store the trampoline address.
     * @param config Optional. Configuration settings for the hook.
     * @return std::string The `name` of the hook if successful, otherwise an empty string.
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

    // --- Mid Hook Creation Methods ---
    /**
     * @brief Creates a mid-function hook at a specific target memory address.
     * @param name A unique, descriptive name for the hook (used as its ID).
     * @param target_address The memory address within a function to hook.
     * @param detour_function The function to be called when the mid-hook is executed (must match `safetyhook::MidHookFn` signature).
     * @param config Optional. Configuration settings for the hook.
     * @return std::string The `name` of the hook if successful, otherwise an empty string.
     */
    std::string create_mid_hook(
        const std::string &name,
        uintptr_t target_address,
        safetyhook::MidHookFn detour_function,
        const HookConfig &config = HookConfig());

    /**
     * @brief Creates a mid-function hook by first finding the target address via an AOB scan.
     * @param name A unique, descriptive name for the hook (used as its ID).
     * @param module_base Base address of the memory module/region to scan.
     * @param module_size Size of the memory module/region to scan.
     * @param aob_pattern_str The AOB pattern string.
     * @param aob_offset Offset to add to the found pattern's address.
     * @param detour_function The mid-hook detour function.
     * @param config Optional. Configuration settings for the hook.
     * @return std::string The `name` of the hook if successful, otherwise an empty string.
     */
    std::string create_mid_hook_aob(
        const std::string &name,
        uintptr_t module_base,
        size_t module_size,
        const std::string &aob_pattern_str,
        ptrdiff_t aob_offset,
        safetyhook::MidHookFn detour_function,
        const HookConfig &config = HookConfig());

    // --- Hook Management Methods ---
    /**
     * @brief Removes a hook identified by its name (ID).
     * @details This also unhooks the function, restoring original behavior.
     * @param hook_id The name (ID) of the hook to remove.
     * @return true if the hook was found and successfully removed, false otherwise.
     */
    bool remove_hook(const std::string &hook_id);

    /**
     * @brief Removes all hooks currently managed by this HookManager instance.
     */
    void remove_all_hooks();

    /**
     * @brief Enables a previously disabled hook.
     * @param hook_id The name (ID) of the hook to enable.
     * @return true if the hook was found and successfully enabled, false otherwise.
     */
    bool enable_hook(const std::string &hook_id);

    /**
     * @brief Disables an active hook temporarily without removing it.
     * @param hook_id The name (ID) of the hook to disable.
     * @return true if the hook was found and successfully disabled, false otherwise.
     */
    bool disable_hook(const std::string &hook_id);

    /**
     * @brief Retrieves the current status of a hook.
     * @param hook_id The name (ID) of the hook.
     * @return HookStatus The current status. Returns `HookStatus::Removed` if the ID is not found.
     */
    HookStatus get_hook_status(const std::string &hook_id) const;

    /**
     * @brief Gets a summary of hook counts categorized by their status.
     * @return std::unordered_map<HookStatus, size_t> A map where keys are statuses and values are counts.
     */
    std::unordered_map<HookStatus, size_t> get_hook_counts() const;

    /**
     * @brief Retrieves a list of hook names (IDs).
     * @param status_filter Optional. If provided, only hooks matching this status will be returned.
     *                      If not provided (std::nullopt), all hook IDs are returned.
     * @return std::vector<std::string> A vector containing the names of the hooks.
     */
    std::vector<std::string> get_hook_ids(std::optional<HookStatus> status_filter = std::nullopt) const;

    /**
     * @brief Retrieves a pointer to an InlineHook object by its ID.
     * @param hook_id The name (ID) of the inline hook.
     * @return InlineHook* Pointer to the InlineHook object if found and is of type Inline, nullptr otherwise.
     *         The lifetime of the returned pointer is managed by the HookManager.
     */
    InlineHook *get_inline_hook(const std::string &hook_id);

    /**
     * @brief Retrieves a pointer to a MidHook object by its ID.
     * @param hook_id The name (ID) of the mid hook.
     * @return MidHook* Pointer to the MidHook object if found and is of type Mid, nullptr otherwise.
     *         The lifetime of the returned pointer is managed by the HookManager.
     */
    MidHook *get_mid_hook(const std::string &hook_id);

private:
    // Prevent copying and assignment of HookManager instances.
    HookManager(const HookManager &) = delete;
    HookManager &operator=(const HookManager &) = delete;

    // Allow moving (though singleton pattern makes this less common for the main instance).
    HookManager(HookManager &&) noexcept = default;
    HookManager &operator=(HookManager &&) noexcept = default;

    // Member variables
    mutable std::recursive_mutex m_hooks_mutex;         /**< Mutex for thread-safe access to hook storage and operations. */
    std::vector<std::unique_ptr<Hook>> m_hooks;         /**< Primary storage for all managed Hook objects. */
    Logger *m_logger;                                   /**< Pointer to the Logger instance for internal logging. */
    std::shared_ptr<safetyhook::Allocator> m_allocator; /**< SafetyHook allocator for managing hook memory. */

    // --- Internal Helper Methods ---
    /** @brief Converts a SafetyHook InlineHook::Error to a descriptive string. */
    std::string error_to_string(const safetyhook::InlineHook::Error &err) const;
    /** @brief Converts a SafetyHook MidHook::Error to a descriptive string. */
    std::string error_to_string(const safetyhook::MidHook::Error &err) const;

    /** @brief Internal: Finds a hook by ID and returns an iterator (non-const). */
    auto find_hook_iterator(const std::string &hook_id) -> decltype(m_hooks.begin());
    /** @brief Internal: Finds a hook by ID and returns a const_iterator (const). */
    auto find_hook_iterator(const std::string &hook_id) const -> decltype(m_hooks.cbegin());

    /** @brief Internal: Checks if a hook with the given name (ID) already exists. */
    bool hook_id_exists(const std::string &hook_id) const;

    /** @brief Internal: Retrieves a raw pointer to a Hook object. Lock should be held by caller. */
    Hook *get_hook_raw_ptr(const std::string &hook_id);
};

#endif // HOOK_MANAGER_HPP
