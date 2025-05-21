#include "hook_manager.hpp"
#include <sstream>
#include <algorithm>

// --- Singleton implementation ---
HookManager &HookManager::getInstance()
{
    static HookManager instance;
    return instance;
}

// --- HookManager implementation ---
HookManager::HookManager(Logger *logger)
    : m_logger(logger ? logger : &Logger::getInstance())
{
    // Initialize the SafetyHook allocator.
    m_allocator = safetyhook::Allocator::global();
    if (!m_allocator)
    {
        m_logger->log(LOG_ERROR, "HookManager: Failed to get SafetyHook global allocator!");
        // Consider throwing an exception here for critical initialization failure
    }
    m_logger->log(LOG_INFO, "HookManager: Initialized");
}

HookManager::~HookManager()
{
    remove_all_hooks();
    m_logger->log(LOG_INFO, "HookManager: Shutdown complete, all hooks removed.");
}

std::string HookManager::error_to_string(const safetyhook::InlineHook::Error &err) const
{
    std::ostringstream oss;
    oss << "SafetyHook InlineHook Error (type " << static_cast<int>(err.type) << "): ";
    switch (err.type)
    {
    case safetyhook::InlineHook::Error::BAD_ALLOCATION:
        oss << "Bad allocation (allocator error: " << static_cast<int>(err.allocator_error) << ")";
        break;
    case safetyhook::InlineHook::Error::FAILED_TO_DECODE_INSTRUCTION:
        oss << "Failed to decode instruction at " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::SHORT_JUMP_IN_TRAMPOLINE:
        oss << "Short jump in trampoline at " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE:
        oss << "IP-relative instruction out of range at " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE:
        oss << "Unsupported instruction in trampoline at " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT:
        oss << "Failed to unprotect memory at " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::NOT_ENOUGH_SPACE:
        oss << "Not enough space for hook at " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    default:
        oss << "Unknown SafetyHook::InlineHook::Error type.";
        break;
    }

    if (err.type == safetyhook::InlineHook::Error::BAD_ALLOCATION)
    {
        oss << " Allocator specific error code: " << static_cast<int>(err.allocator_error);
    }
    return oss.str();
}

std::string HookManager::error_to_string(const safetyhook::MidHook::Error &err) const
{
    std::ostringstream oss;
    oss << "SafetyHook MidHook Error (type " << static_cast<int>(err.type) << "): ";
    switch (err.type)
    {
    case safetyhook::MidHook::Error::BAD_ALLOCATION:
        oss << "Bad allocation (allocator error: " << static_cast<int>(err.allocator_error) << ")";
        break;
    case safetyhook::MidHook::Error::BAD_INLINE_HOOK:
        oss << "Bad inline hook: " << error_to_string(err.inline_hook_error);
        break;
    default:
        oss << "Unknown SafetyHook::MidHook::Error type.";
        break;
    }

    return oss.str();
}

auto HookManager::find_hook(const std::string &hook_id) -> decltype(m_hooks.begin())
{
    return std::find_if(m_hooks.begin(), m_hooks.end(),
                        [&](const auto &hook)
                        { return hook->getName() == hook_id; });
}

auto HookManager::find_hook(const std::string &hook_id) const -> decltype(m_hooks.cbegin())
{
    return std::find_if(m_hooks.cbegin(), m_hooks.cend(),
                        [&](const auto &hook)
                        { return hook->getName() == hook_id; });
}

bool HookManager::hook_id_exists(const std::string &hook_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    return find_hook(hook_id) != m_hooks.cend();
}

std::string HookManager::create_inline_hook(
    const std::string &name,
    uintptr_t target_address,
    void *detour_function,
    void **original_trampoline,
    const HookConfig &config)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    if (!m_allocator)
    {
        m_logger->log(LOG_ERROR, "HookManager: Allocator not initialized. Cannot create hook '" + name + "'.");
        return "";
    }
    if (target_address == 0)
    {
        m_logger->log(LOG_ERROR, "HookManager: Attempted to hook NULL address for '" + name + "'.");
        return "";
    }
    if (detour_function == nullptr)
    {
        m_logger->log(LOG_ERROR, "HookManager: Detour function is NULL for '" + name + "'.");
        return "";
    }
    if (original_trampoline == nullptr)
    {
        m_logger->log(LOG_ERROR, "HookManager: Original trampoline pointer is NULL for '" + name + "'.");
        return "";
    }

    // Check if a hook with the same name already exists to prevent duplicates
    if (hook_id_exists(name))
    {
        m_logger->log(LOG_ERROR, "HookManager: Hook with name '" + name + "' already exists.");
        return "";
    }

    try
    {
        // Setup flags for SafetyHook
        safetyhook::InlineHook::Flags flags = static_cast<safetyhook::InlineHook::Flags>(config.flags);
        if (!config.autoEnable)
        {
            flags = static_cast<safetyhook::InlineHook::Flags>(flags | safetyhook::InlineHook::StartDisabled);
        }

        // Create the inline hook using SafetyHook
        auto hook_result = safetyhook::InlineHook::create(
            m_allocator,
            reinterpret_cast<void *>(target_address),
            detour_function,
            flags);

        if (!hook_result)
        {
            // Creation failed, log the error.
            m_logger->log(LOG_ERROR, "HookManager: Failed to create SafetyHook::InlineHook for '" + name + "' at " +
                                         format_address(target_address) + ". Error: " + error_to_string(hook_result.error()));
            return "";
        }

        // Move the hook out of the expected result
        auto sh_hook = std::make_unique<safetyhook::InlineHook>(std::move(hook_result.value()));

        // Store the trampoline pointer for original function calls
        *original_trampoline = sh_hook->original<void *>();

        // Set initial hook status based on configuration
        HookStatus initial_status = config.autoEnable ? HookStatus::Active : HookStatus::Disabled;

        // Create and add the new hook to our list
        auto inline_hook = std::make_unique<InlineHook>(name, target_address, std::move(sh_hook), initial_status);
        m_hooks.push_back(std::move(inline_hook));

        std::string auto_enable_status_str = config.autoEnable ? "and enabled" : "but disabled";
        m_logger->log(LOG_INFO, "HookManager: Successfully created " +
                                    auto_enable_status_str +
                                    " inline hook for '" + name + "' at " +
                                    format_address(target_address));
        return name; // Use name as ID.
    }
    catch (const std::exception &e)
    {
        m_logger->log(LOG_ERROR, "HookManager: std::exception during InlineHook creation for '" + name + "': " + e.what());
        return "";
    }
    catch (...)
    {
        m_logger->log(LOG_ERROR, "HookManager: Unknown exception during InlineHook creation for '" + name + "'.");
        return "";
    }
}

std::string HookManager::create_inline_hook_aob(
    const std::string &name,
    uintptr_t module_base,
    size_t module_size,
    const std::string &aob_pattern_str,
    ptrdiff_t aob_offset,
    void *detour_function,
    void **original_trampoline,
    const HookConfig &config)
{
    m_logger->log(LOG_DEBUG, "HookManager: Attempting AOB scan for hook '" + name + "' with pattern '" + aob_pattern_str + "'.");

    std::vector<BYTE> pattern_bytes = parseAOB(aob_pattern_str);
    if (pattern_bytes.empty())
    {
        m_logger->log(LOG_ERROR, "HookManager: Failed to parse AOB pattern '" + aob_pattern_str + "' for '" + name + "'.");
        return "";
    }

    BYTE *found_address = FindPattern(reinterpret_cast<BYTE *>(module_base), module_size, pattern_bytes);
    if (!found_address)
    {
        m_logger->log(LOG_ERROR, "HookManager: AOB pattern '" + aob_pattern_str + "' not found for '" + name + "'.");
        return "";
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address) + aob_offset;
    m_logger->log(LOG_INFO, "HookManager: AOB pattern for '" + name + "' found at " + format_address(reinterpret_cast<uintptr_t>(found_address)) +
                                ". Target hook address: " + format_address(target_address) +
                                " (Base + Offset: " + format_hex(static_cast<int>(aob_offset)) + ")");

    return create_inline_hook(name, target_address, detour_function, original_trampoline, config);
}

std::string HookManager::create_mid_hook(
    const std::string &name,
    uintptr_t target_address,
    safetyhook::MidHookFn detour_function,
    const HookConfig &config)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    if (!m_allocator)
    {
        m_logger->log(LOG_ERROR, "HookManager: Allocator not initialized. Cannot create mid hook '" + name + "'.");
        return "";
    }
    if (target_address == 0)
    {
        m_logger->log(LOG_ERROR, "HookManager: Attempted to hook NULL address for mid hook '" + name + "'.");
        return "";
    }
    if (detour_function == nullptr)
    {
        m_logger->log(LOG_ERROR, "HookManager: Detour function is NULL for mid hook '" + name + "'.");
        return "";
    }

    // Check if a hook with the same name already exists to prevent duplicates
    if (hook_id_exists(name))
    {
        m_logger->log(LOG_ERROR, "HookManager: Hook with name '" + name + "' already exists.");
        return "";
    }

    try
    {
        // Setup flags for SafetyHook
        safetyhook::MidHook::Flags flags = static_cast<safetyhook::MidHook::Flags>(config.flags);
        if (!config.autoEnable)
        {
            flags = static_cast<safetyhook::MidHook::Flags>(flags | safetyhook::MidHook::StartDisabled);
        }

        // Create the mid hook using SafetyHook
        auto hook_result = safetyhook::MidHook::create(
            m_allocator,
            reinterpret_cast<void *>(target_address),
            detour_function,
            flags);

        if (!hook_result)
        {
            // Creation failed, log the error.
            m_logger->log(LOG_ERROR, "HookManager: Failed to create SafetyHook::MidHook for '" + name + "' at " +
                                         format_address(target_address) + ". Error: " + error_to_string(hook_result.error()));
            return "";
        }

        // Move the hook out of the expected result
        auto sh_hook = std::make_unique<safetyhook::MidHook>(std::move(hook_result.value()));

        // Set initial hook status based on configuration
        HookStatus initial_status = config.autoEnable ? HookStatus::Active : HookStatus::Disabled;

        // Create and add the new hook to our list
        auto mid_hook = std::make_unique<MidHook>(name, target_address, std::move(sh_hook), initial_status);
        m_hooks.push_back(std::move(mid_hook));

        std::string auto_enable_status_str = config.autoEnable ? "and enabled" : "but disabled";
        m_logger->log(LOG_INFO, "HookManager: Successfully created " +
                                    auto_enable_status_str +
                                    " mid hook for '" + name + "' at " +
                                    format_address(target_address));
        return name; // Use name as ID.
    }
    catch (const std::exception &e)
    {
        m_logger->log(LOG_ERROR, "HookManager: std::exception during MidHook creation for '" + name + "': " + e.what());
        return "";
    }
    catch (...)
    {
        m_logger->log(LOG_ERROR, "HookManager: Unknown exception during MidHook creation for '" + name + "'.");
        return "";
    }
}

std::string HookManager::create_mid_hook_aob(
    const std::string &name,
    uintptr_t module_base,
    size_t module_size,
    const std::string &aob_pattern_str,
    ptrdiff_t aob_offset,
    safetyhook::MidHookFn detour_function,
    const HookConfig &config)
{
    m_logger->log(LOG_DEBUG, "HookManager: Attempting AOB scan for mid hook '" + name + "' with pattern '" + aob_pattern_str + "'.");

    std::vector<BYTE> pattern_bytes = parseAOB(aob_pattern_str);
    if (pattern_bytes.empty())
    {
        m_logger->log(LOG_ERROR, "HookManager: Failed to parse AOB pattern '" + aob_pattern_str + "' for mid hook '" + name + "'.");
        return "";
    }

    BYTE *found_address = FindPattern(reinterpret_cast<BYTE *>(module_base), module_size, pattern_bytes);
    if (!found_address)
    {
        m_logger->log(LOG_ERROR, "HookManager: AOB pattern '" + aob_pattern_str + "' not found for mid hook '" + name + "'.");
        return "";
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address) + aob_offset;
    m_logger->log(LOG_INFO, "HookManager: AOB pattern for mid hook '" + name + "' found at " +
                                format_address(reinterpret_cast<uintptr_t>(found_address)) +
                                ". Target hook address: " + format_address(target_address) +
                                " (Base + Offset: " + format_hex(static_cast<int>(aob_offset)) + ")");

    return create_mid_hook(name, target_address, detour_function, config);
}

bool HookManager::remove_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    auto it = find_hook(hook_id);
    if (it != m_hooks.end())
    {
        std::string name = (*it)->getName();
        HookType type = (*it)->getType();
        m_hooks.erase(it); // This calls ~std::unique_ptr() which calls the Hook destructor

        m_logger->log(LOG_INFO, "HookManager: Hook '" + name + "' (" +
                                    (type == HookType::Inline ? "inline" : "mid") +
                                    ") removed and unhooked.");
        return true;
    }

    m_logger->log(LOG_WARNING, "HookManager: Hook ID '" + hook_id + "' not found for removal.");
    return false;
}

void HookManager::remove_all_hooks()
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    if (!m_hooks.empty())
    {
        m_logger->log(LOG_INFO, "HookManager: Removing all " + std::to_string(m_hooks.size()) + " managed hooks...");
        m_hooks.clear(); // This will call destructors in reverse order of construction for elements
        m_logger->log(LOG_INFO, "HookManager: All managed hooks have been removed.");
    }
    else
    {
        m_logger->log(LOG_DEBUG, "HookManager: remove_all_hooks called, but no hooks were active.");
    }
}

bool HookManager::enable_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    auto it = find_hook(hook_id);
    if (it != m_hooks.end())
    {
        bool result = (*it)->enable();
        if (result)
        {
            m_logger->log(LOG_INFO, "HookManager: Hook '" + hook_id + "' enabled.");
        }
        else
        {
            m_logger->log(LOG_WARNING, "HookManager: Failed to enable hook '" + hook_id + "'.");
        }
        return result;
    }

    m_logger->log(LOG_WARNING, "HookManager: Hook ID '" + hook_id + "' not found for enable operation.");
    return false;
}

bool HookManager::disable_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    auto it = find_hook(hook_id);
    if (it != m_hooks.end())
    {
        bool result = (*it)->disable();
        if (result)
        {
            m_logger->log(LOG_INFO, "HookManager: Hook '" + hook_id + "' disabled.");
        }
        else
        {
            m_logger->log(LOG_WARNING, "HookManager: Failed to disable hook '" + hook_id + "'.");
        }
        return result;
    }

    m_logger->log(LOG_WARNING, "HookManager: Hook ID '" + hook_id + "' not found for disable operation.");
    return false;
}

HookStatus HookManager::get_hook_status(const std::string &hook_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    auto it = find_hook(hook_id);
    if (it != m_hooks.cend())
    {
        return (*it)->getStatus();
    }

    return HookStatus::Removed; // Not found means effectively removed
}

std::unordered_map<HookStatus, size_t> HookManager::get_hook_counts() const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    std::unordered_map<HookStatus, size_t> counts;

    // Initialize all statuses with zero count
    counts[HookStatus::Active] = 0;
    counts[HookStatus::Disabled] = 0;
    counts[HookStatus::Failed] = 0;
    counts[HookStatus::Removed] = 0;

    // Count hooks by status
    for (const auto &hook : m_hooks)
    {
        counts[hook->getStatus()]++;
    }

    return counts;
}

std::vector<std::string> HookManager::get_hook_ids(HookStatus status_filter) const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    std::vector<std::string> ids;
    for (const auto &hook : m_hooks)
    {
        if (hook->getStatus() == status_filter)
        {
            ids.push_back(hook->getName());
        }
    }

    return ids;
}

Hook *HookManager::get_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);

    auto it = find_hook(hook_id);
    return (it != m_hooks.end()) ? it->get() : nullptr;
}

InlineHook *HookManager::get_inline_hook(const std::string &hook_id)
{
    Hook *hook = get_hook(hook_id);
    if (hook && hook->getType() == HookType::Inline)
    {
        return static_cast<InlineHook *>(hook);
    }
    return nullptr;
}

MidHook *HookManager::get_mid_hook(const std::string &hook_id)
{
    Hook *hook = get_hook(hook_id);
    if (hook && hook->getType() == HookType::Mid)
    {
        return static_cast<MidHook *>(hook);
    }
    return nullptr;
}
