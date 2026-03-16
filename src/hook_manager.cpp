
#include "DetourModKit/hook_manager.hpp"

#include <sstream>
#include <algorithm>
#include <cstddef>

using namespace DetourModKit;
using namespace DetourModKit::Scanner;
using namespace DetourModKit::String;

// --- Singleton implementation ---
HookManager &HookManager::getInstance()
{
    static HookManager instance;
    return instance;
}

// --- HookManager implementation ---
HookManager::HookManager(Logger *logger) // Explicit constructor
    : m_logger(logger ? logger : &Logger::getInstance())
{
    m_allocator = safetyhook::Allocator::global();
    if (!m_allocator)
    {
        m_logger->error("HookManager: Failed to get SafetyHook global allocator! Hook creation will fail.");
    }
    else
    {
        m_logger->info("HookManager: SafetyHook global allocator obtained.");
    }
    m_logger->info("HookManager: Initialized.");
}

HookManager::~HookManager()
{
    remove_all_hooks();
    m_logger->info("HookManager: Shutdown complete. All managed hooks should be removed and unhooked.");
}

std::string HookManager::error_to_string(const safetyhook::InlineHook::Error &err) const
{
    std::ostringstream oss;
    oss << "SafetyHook InlineHook Error (Type: " << static_cast<int>(err.type) << "): ";
    switch (err.type)
    {
    case safetyhook::InlineHook::Error::BAD_ALLOCATION:
        oss << "Bad allocation (Allocator error: " << static_cast<int>(err.allocator_error) << ")";
        break;
    case safetyhook::InlineHook::Error::FAILED_TO_DECODE_INSTRUCTION:
        oss << "Failed to decode instruction at address " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::SHORT_JUMP_IN_TRAMPOLINE:
        oss << "Short jump found in trampoline at address " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE:
        oss << "IP-relative instruction out of range at address " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE:
        oss << "Unsupported instruction in trampoline at address " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT:
        oss << "Failed to unprotect memory at address " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::NOT_ENOUGH_SPACE:
        oss << "Not enough space for the hook (prologue too short) at address " << format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    default:
        oss << "Unknown SafetyHook::InlineHook::Error type.";
        break;
    }
    if (err.type == safetyhook::InlineHook::Error::BAD_ALLOCATION)
    {
        oss << "; Allocator specific error code: " << static_cast<int>(err.allocator_error);
    }
    return oss.str();
}

std::string HookManager::error_to_string(const safetyhook::MidHook::Error &err) const
{
    std::ostringstream oss;
    oss << "SafetyHook MidHook Error (Type: " << static_cast<int>(err.type) << "): ";
    switch (err.type)
    {
    case safetyhook::MidHook::Error::BAD_ALLOCATION:
        oss << "Bad allocation (Allocator error: " << static_cast<int>(err.allocator_error) << ")";
        break;
    case safetyhook::MidHook::Error::BAD_INLINE_HOOK:
        oss << "Bad underlying inline hook. Details: " << error_to_string(err.inline_hook_error);
        break;
    default:
        oss << "Unknown SafetyHook::MidHook::Error type.";
        break;
    }
    return oss.str();
}

auto HookManager::find_hook_iterator(const std::string &hook_id) -> decltype(m_hooks.begin())
{
    return std::find_if(m_hooks.begin(), m_hooks.end(),
                        [&](const auto &hook_ptr)
                        { return hook_ptr->getName() == hook_id; });
}

auto HookManager::find_hook_iterator(const std::string &hook_id) const -> decltype(m_hooks.cbegin())
{
    return std::find_if(m_hooks.cbegin(), m_hooks.cend(),
                        [&](const auto &hook_ptr)
                        { return hook_ptr->getName() == hook_id; });
}

bool HookManager::hook_id_exists(const std::string &hook_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    return find_hook_iterator(hook_id) != m_hooks.cend();
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
        m_logger->error("HookManager: Allocator not available. Cannot create inline hook '{}'.", name);
        return "";
    }
    if (target_address == 0)
    {
        m_logger->error("HookManager: Target address is NULL for inline hook '{}'.", name);
        return "";
    }
    if (detour_function == nullptr)
    {
        m_logger->error("HookManager: Detour function is NULL for inline hook '{}'.", name);
        return "";
    }
    if (original_trampoline == nullptr)
    {
        m_logger->error("HookManager: Original trampoline pointer (output) is NULL for inline hook '{}'.", name);
        return "";
    }
    *original_trampoline = nullptr;

    if (hook_id_exists(name))
    {
        m_logger->error("HookManager: A hook with the name '{}' already exists.", name);
        return "";
    }

    try
    {
        safetyhook::InlineHook::Flags sh_flags = static_cast<safetyhook::InlineHook::Flags>(config.flags);
        if (!config.autoEnable)
        {
            sh_flags = static_cast<safetyhook::InlineHook::Flags>(
                static_cast<uint32_t>(sh_flags) | static_cast<uint32_t>(safetyhook::InlineHook::StartDisabled));
        }

        auto hook_creation_result = safetyhook::InlineHook::create(
            m_allocator,
            reinterpret_cast<void *>(target_address),
            detour_function,
            sh_flags);

        if (!hook_creation_result)
        {
            m_logger->error("HookManager: Failed to create SafetyHook::InlineHook for '{}' at {}. Error: {}",
                            name, format_address(target_address), error_to_string(hook_creation_result.error()));
            return "";
        }

        auto sh_inline_hook_ptr = std::make_unique<safetyhook::InlineHook>(std::move(hook_creation_result.value()));
        *original_trampoline = sh_inline_hook_ptr->original<void *>();

        HookStatus initial_status;
        if (sh_inline_hook_ptr->enabled())
        {
            initial_status = HookStatus::Active;
        }
        else
        {
            initial_status = HookStatus::Disabled;
            if (config.autoEnable)
            {
                m_logger->warning("HookManager: Inline hook '{}' was configured for auto-enable but is currently disabled post-creation.", name);
            }
        }

        auto managed_hook = std::make_unique<InlineHook>(name, target_address, std::move(sh_inline_hook_ptr), initial_status);
        m_hooks.push_back(std::move(managed_hook));

        std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : " (created disabled)";
        m_logger->info("HookManager: Successfully created {} inline hook '{}' targeting {}.",
                       status_message, name, format_address(target_address));
        return name;
    }
    catch (const std::exception &e)
    {
        m_logger->error("HookManager: An std::exception occurred during inline hook creation for '{}': {}", name, e.what());
        return "";
    }
    catch (...)
    {
        m_logger->error("HookManager: An unknown exception occurred during inline hook creation for '{}'.", name);
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
    m_logger->debug("HookManager: Attempting AOB scan for inline hook '{}' with pattern: \"{}\", offset: {}.",
                    name, aob_pattern_str, format_hex(static_cast<int>(aob_offset), 0));

    std::vector<std::byte> pattern_bytes = parseAOB(aob_pattern_str);
    if (pattern_bytes.empty())
    {
        m_logger->error("HookManager: AOB pattern parsing failed for inline hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return "";
    }

    std::byte *found_address_start = FindPattern(reinterpret_cast<std::byte *>(module_base), module_size, pattern_bytes);
    if (!found_address_start)
    {
        m_logger->error("HookManager: AOB pattern not found for inline hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return "";
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger->info("HookManager: AOB pattern for inline hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
                   name, format_address(reinterpret_cast<uintptr_t>(found_address_start)),
                   format_hex(static_cast<int>(aob_offset), 0), format_address(target_address));

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
        m_logger->error("HookManager: Allocator not available. Cannot create mid hook '{}'.", name);
        return "";
    }
    if (target_address == 0)
    {
        m_logger->error("HookManager: Target address is NULL for mid hook '{}'.", name);
        return "";
    }
    if (detour_function == nullptr)
    {
        m_logger->error("HookManager: Detour function is NULL for mid hook '{}'.", name);
        return "";
    }

    if (hook_id_exists(name))
    {
        m_logger->error("HookManager: A hook with the name '{}' already exists.", name);
        return "";
    }

    try
    {
        safetyhook::MidHook::Flags sh_flags = static_cast<safetyhook::MidHook::Flags>(config.flags);
        if (!config.autoEnable)
        {
            sh_flags = static_cast<safetyhook::MidHook::Flags>(
                static_cast<uint32_t>(sh_flags) | static_cast<uint32_t>(safetyhook::MidHook::StartDisabled));
        }

        auto hook_creation_result = safetyhook::MidHook::create(
            m_allocator,
            reinterpret_cast<void *>(target_address),
            detour_function,
            sh_flags);

        if (!hook_creation_result)
        {
            m_logger->error("HookManager: Failed to create SafetyHook::MidHook for '{}' at {}. Error: {}",
                            name, format_address(target_address), error_to_string(hook_creation_result.error()));
            return "";
        }

        auto sh_mid_hook_ptr = std::make_unique<safetyhook::MidHook>(std::move(hook_creation_result.value()));

        HookStatus initial_status;
        if (sh_mid_hook_ptr->enabled())
        {
            initial_status = HookStatus::Active;
        }
        else
        {
            initial_status = HookStatus::Disabled;
            if (config.autoEnable)
            {
                m_logger->warning("HookManager: Mid hook '{}' was configured for auto-enable but is currently disabled post-creation.", name);
            }
        }

        auto managed_hook = std::make_unique<MidHook>(name, target_address, std::move(sh_mid_hook_ptr), initial_status);
        m_hooks.push_back(std::move(managed_hook));

        std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : " (created disabled)";
        m_logger->info("HookManager: Successfully created {} mid hook '{}' targeting {}.",
                       status_message, name, format_address(target_address));
        return name;
    }
    catch (const std::exception &e)
    {
        m_logger->error("HookManager: An std::exception occurred during mid hook creation for '{}': {}", name, e.what());
        return "";
    }
    catch (...)
    {
        m_logger->error("HookManager: An unknown exception occurred during mid hook creation for '{}'.", name);
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
    m_logger->debug("HookManager: Attempting AOB scan for mid hook '{}' with pattern: \"{}\", offset: {}.",
                    name, aob_pattern_str, format_hex(static_cast<int>(aob_offset), 0));

    std::vector<std::byte> pattern_bytes = parseAOB(aob_pattern_str);
    if (pattern_bytes.empty())
    {
        m_logger->error("HookManager: AOB pattern parsing failed for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return "";
    }

    std::byte *found_address_start = FindPattern(reinterpret_cast<std::byte *>(module_base), module_size, pattern_bytes);
    if (!found_address_start)
    {
        m_logger->error("HookManager: AOB pattern not found for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return "";
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger->info("HookManager: AOB pattern for mid hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
                   name, format_address(reinterpret_cast<uintptr_t>(found_address_start)),
                   format_hex(static_cast<int>(aob_offset), 0), format_address(target_address));

    return create_mid_hook(name, target_address, detour_function, config);
}

bool HookManager::remove_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    auto it = find_hook_iterator(hook_id);
    if (it != m_hooks.end())
    {
        std::string name_of_removed_hook = (*it)->getName();
        HookType type_of_removed_hook = (*it)->getType();
        m_hooks.erase(it);
        m_logger->info("HookManager: Hook '{}' of type '{}' has been removed and unhooked.",
                       name_of_removed_hook, (type_of_removed_hook == HookType::Inline ? "Inline" : "Mid"));
        return true;
    }
    m_logger->warning("HookManager: Attempted to remove hook with ID '{}', but it was not found.", hook_id);
    return false;
}

void HookManager::remove_all_hooks()
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    if (!m_hooks.empty())
    {
        size_t num_hooks = m_hooks.size();
        m_logger->info("HookManager: Removing all {} managed hooks...", num_hooks);
        m_hooks.clear();
        m_logger->info("HookManager: All {} managed hooks have been removed and unhooked.", num_hooks);
    }
    else
    {
        m_logger->debug("HookManager: remove_all_hooks called, but no hooks were active to remove.");
    }
}

bool HookManager::enable_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    auto it = find_hook_iterator(hook_id);
    if (it != m_hooks.end())
    {
        Hook *hook = it->get();
        if (hook->getStatus() == HookStatus::Disabled)
        {
            if (hook->enable())
            {
                m_logger->info("HookManager: Hook '{}' successfully enabled.", hook_id);
                return true;
            }
            else
            {
                m_logger->error("HookManager: Failed to enable hook '{}'. Underlying SafetyHook call may have failed.", hook_id);
                return false;
            }
        }
        else if (hook->getStatus() == HookStatus::Active)
        {
            m_logger->debug("HookManager: Hook '{}' is already active. Enable request ignored.", hook_id);
            return true;
        }
        else
        {
            m_logger->warning("HookManager: Hook '{}' cannot be enabled. Current status: {}", hook_id, Hook::statusToString(hook->getStatus()));
            return false;
        }
    }
    m_logger->warning("HookManager: Hook ID '{}' not found for enable operation.", hook_id);
    return false;
}

bool HookManager::disable_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    auto it = find_hook_iterator(hook_id);
    if (it != m_hooks.end())
    {
        Hook *hook = it->get();
        if (hook->getStatus() == HookStatus::Active)
        {
            if (hook->disable())
            {
                m_logger->info("HookManager: Hook '{}' successfully disabled.", hook_id);
                return true;
            }
            else
            {
                m_logger->error("HookManager: Failed to disable hook '{}'. Underlying SafetyHook call may have failed.", hook_id);
                return false;
            }
        }
        else if (hook->getStatus() == HookStatus::Disabled)
        {
            m_logger->debug("HookManager: Hook '{}' is already disabled. Disable request ignored.", hook_id);
            return true;
        }
        else
        {
            m_logger->warning("HookManager: Hook '{}' cannot be disabled. Current status: {}", hook_id, Hook::statusToString(hook->getStatus()));
            return false;
        }
    }
    m_logger->warning("HookManager: Hook ID '{}' not found for disable operation.", hook_id);
    return false;
}

HookStatus HookManager::get_hook_status(const std::string &hook_id) const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    auto it = find_hook_iterator(hook_id);
    if (it != m_hooks.cend())
    {
        return (*it)->getStatus();
    }
    return HookStatus::Removed;
}

std::unordered_map<HookStatus, size_t> HookManager::get_hook_counts() const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    std::unordered_map<HookStatus, size_t> counts;
    counts[HookStatus::Active] = 0;
    counts[HookStatus::Disabled] = 0;
    counts[HookStatus::Failed] = 0;
    counts[HookStatus::Removed] = 0;
    for (const auto &hook_ptr : m_hooks)
    {
        counts[hook_ptr->getStatus()]++;
    }
    return counts;
}

std::vector<std::string> HookManager::get_hook_ids(std::optional<HookStatus> status_filter) const
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    std::vector<std::string> ids;
    ids.reserve(m_hooks.size());
    for (const auto &hook_ptr : m_hooks)
    {
        if (!status_filter.has_value() || hook_ptr->getStatus() == status_filter.value())
        {
            ids.push_back(hook_ptr->getName());
        }
    }
    return ids;
}

Hook *HookManager::get_hook_raw_ptr(const std::string &hook_id)
{
    auto it = find_hook_iterator(hook_id);
    return (it != m_hooks.end()) ? it->get() : nullptr;
}

InlineHook *HookManager::get_inline_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    Hook *base_hook_ptr = get_hook_raw_ptr(hook_id);
    if (base_hook_ptr && base_hook_ptr->getType() == HookType::Inline)
    {
        return static_cast<InlineHook *>(base_hook_ptr);
    }
    return nullptr;
}

MidHook *HookManager::get_mid_hook(const std::string &hook_id)
{
    std::lock_guard<std::recursive_mutex> lock(m_hooks_mutex);
    Hook *base_hook_ptr = get_hook_raw_ptr(hook_id);
    if (base_hook_ptr && base_hook_ptr->getType() == HookType::Mid)
    {
        return static_cast<MidHook *>(base_hook_ptr);
    }
    return nullptr;
}
