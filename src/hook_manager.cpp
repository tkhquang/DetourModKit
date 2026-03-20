#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/format.hpp"

#include <sstream>
#include <algorithm>
#include <cstddef>

using namespace DetourModKit;
using namespace DetourModKit::Scanner;

// --- Singleton implementation ---
HookManager &HookManager::get_instance()
{
    static HookManager instance;
    return instance;
}

// --- HookManager implementation ---
HookManager::HookManager(Logger &logger)
    : m_logger(logger)
{
    m_allocator = safetyhook::Allocator::global();
    if (!m_allocator)
    {
        m_logger.error("HookManager: Failed to get SafetyHook global allocator! Hook creation will fail.");
    }
    else
    {
        m_logger.info("HookManager: SafetyHook global allocator obtained.");
    }
    m_logger.info("HookManager: Initialized.");
}

HookManager::~HookManager()
{
    if (!m_shutdown_called)
    {
        // If shutdown() was not called explicitly, we still need to remove hooks
        // but we cannot safely log because Logger might be destroyed already.
        // This is a fallback for cases where DMK_Shutdown() was not called.
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
        m_hooks.clear();
    }
}

void HookManager::shutdown()
{
    if (m_shutdown_called)
    {
        return; // Already shut down
    }
    m_shutdown_called = true;

    // Remove all hooks without logging to avoid use-after-free if Logger is destroyed
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    m_hooks.clear();
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
        oss << "Failed to decode instruction at address " << DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::SHORT_JUMP_IN_TRAMPOLINE:
        oss << "Short jump found in trampoline at address " << DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE:
        oss << "IP-relative instruction out of range at address " << DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE:
        oss << "Unsupported instruction in trampoline at address " << DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT:
        oss << "Failed to unprotect memory at address " << DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));
        break;
    case safetyhook::InlineHook::Error::NOT_ENOUGH_SPACE:
        oss << "Not enough space for the hook (prologue too short) at address " << DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));
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

// Non-locking internal helpers - caller must hold m_hooks_mutex
bool HookManager::hook_id_exists_locked(const std::string &hook_id) const
{
    return m_hooks.find(hook_id) != m_hooks.end();
}

Hook *HookManager::get_hook_raw_ptr_locked(const std::string &hook_id)
{
    auto it = m_hooks.find(hook_id);
    return (it != m_hooks.end()) ? it->second.get() : nullptr;
}

std::expected<std::string, HookError> HookManager::create_inline_hook(
    const std::string &name,
    uintptr_t target_address,
    void *detour_function,
    void **original_trampoline,
    const HookConfig &config)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

    if (!m_allocator)
    {
        m_logger.error("HookManager: Allocator not available. Cannot create inline hook '{}'.", name);
        return std::unexpected(HookError::AllocatorNotAvailable);
    }
    if (target_address == 0)
    {
        m_logger.error("HookManager: Target address is NULL for inline hook '{}'.", name);
        return std::unexpected(HookError::InvalidTargetAddress);
    }
    if (detour_function == nullptr)
    {
        m_logger.error("HookManager: Detour function is NULL for inline hook '{}'.", name);
        return std::unexpected(HookError::InvalidDetourFunction);
    }
    if (original_trampoline == nullptr)
    {
        m_logger.error("HookManager: Original trampoline pointer (output) is NULL for inline hook '{}'.", name);
        return std::unexpected(HookError::InvalidTrampolinePointer);
    }
    *original_trampoline = nullptr;

    if (hook_id_exists_locked(name))
    {
        m_logger.error("HookManager: A hook with the name '{}' already exists.", name);
        return std::unexpected(HookError::HookAlreadyExists);
    }

    try
    {
        safetyhook::InlineHook::Flags sh_flags = config.inline_flags;
        if (!config.auto_enable)
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
            m_logger.error("HookManager: Failed to create SafetyHook::InlineHook for '{}' at {}. Error: {}",
                           name, DetourModKit::Format::format_address(target_address), error_to_string(hook_creation_result.error()));
            return std::unexpected(HookError::SafetyHookError);
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
            if (config.auto_enable)
            {
                m_logger.warning("HookManager: Inline hook '{}' was configured for auto-enable but is currently disabled post-creation.", name);
            }
        }

        auto managed_hook = std::make_unique<InlineHook>(name, target_address, std::move(sh_inline_hook_ptr), initial_status);
        m_hooks.emplace(name, std::move(managed_hook));

        std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : " (created disabled)";
        m_logger.info("HookManager: Successfully created {} inline hook '{}' targeting {}.",
                      status_message, name, DetourModKit::Format::format_address(target_address));
        return name;
    }
    catch (const std::exception &e)
    {
        m_logger.error("HookManager: An std::exception occurred during inline hook creation for '{}': {}", name, e.what());
        return std::unexpected(HookError::UnknownError);
    }
    catch (...)
    {
        m_logger.error("HookManager: An unknown exception occurred during inline hook creation for '{}'.", name);
        return std::unexpected(HookError::UnknownError);
    }
}

std::expected<std::string, HookError> HookManager::create_inline_hook_aob(
    const std::string &name,
    uintptr_t module_base,
    size_t module_size,
    const std::string &aob_pattern_str,
    ptrdiff_t aob_offset,
    void *detour_function,
    void **original_trampoline,
    const HookConfig &config)
{
    m_logger.debug("HookManager: Attempting AOB scan for inline hook '{}' with pattern: \"{}\", offset: {}.",
                   name, aob_pattern_str, DetourModKit::Format::format_hex(static_cast<int>(aob_offset), 0));

    auto pattern = parse_aob(aob_pattern_str);
    if (!pattern.has_value())
    {
        m_logger.error("HookManager: AOB pattern parsing failed for inline hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    std::byte *found_address_start = find_pattern(reinterpret_cast<std::byte *>(module_base), module_size, pattern.value());
    if (!found_address_start)
    {
        m_logger.error("HookManager: AOB pattern not found for inline hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger.info("HookManager: AOB pattern for inline hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
                  name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(found_address_start)),
                  DetourModKit::Format::format_hex(static_cast<int>(aob_offset), 0), DetourModKit::Format::format_address(target_address));

    return create_inline_hook(name, target_address, detour_function, original_trampoline, config);
}

std::expected<std::string, HookError> HookManager::create_mid_hook(
    const std::string &name,
    uintptr_t target_address,
    safetyhook::MidHookFn detour_function,
    const HookConfig &config)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

    if (!m_allocator)
    {
        m_logger.error("HookManager: Allocator not available. Cannot create mid hook '{}'.", name);
        return std::unexpected(HookError::AllocatorNotAvailable);
    }
    if (target_address == 0)
    {
        m_logger.error("HookManager: Target address is NULL for mid hook '{}'.", name);
        return std::unexpected(HookError::InvalidTargetAddress);
    }
    if (detour_function == nullptr)
    {
        m_logger.error("HookManager: Detour function is NULL for mid hook '{}'.", name);
        return std::unexpected(HookError::InvalidDetourFunction);
    }

    if (hook_id_exists_locked(name))
    {
        m_logger.error("HookManager: A hook with the name '{}' already exists.", name);
        return std::unexpected(HookError::HookAlreadyExists);
    }

    try
    {
        safetyhook::MidHook::Flags sh_flags = config.mid_flags;
        if (!config.auto_enable)
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
            m_logger.error("HookManager: Failed to create SafetyHook::MidHook for '{}' at {}. Error: {}",
                           name, DetourModKit::Format::format_address(target_address), error_to_string(hook_creation_result.error()));
            return std::unexpected(HookError::SafetyHookError);
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
            if (config.auto_enable)
            {
                m_logger.warning("HookManager: Mid hook '{}' was configured for auto-enable but is currently disabled post-creation.", name);
            }
        }

        auto managed_hook = std::make_unique<MidHook>(name, target_address, std::move(sh_mid_hook_ptr), initial_status);
        m_hooks.emplace(name, std::move(managed_hook));

        std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : " (created disabled)";
        m_logger.info("HookManager: Successfully created {} mid hook '{}' targeting {}.",
                      status_message, name, DetourModKit::Format::format_address(target_address));
        return name;
    }
    catch (const std::exception &e)
    {
        m_logger.error("HookManager: An std::exception occurred during mid hook creation for '{}': {}", name, e.what());
        return std::unexpected(HookError::UnknownError);
    }
    catch (...)
    {
        m_logger.error("HookManager: An unknown exception occurred during mid hook creation for '{}'.", name);
        return std::unexpected(HookError::UnknownError);
    }
}

std::expected<std::string, HookError> HookManager::create_mid_hook_aob(
    const std::string &name,
    uintptr_t module_base,
    size_t module_size,
    const std::string &aob_pattern_str,
    ptrdiff_t aob_offset,
    safetyhook::MidHookFn detour_function,
    const HookConfig &config)
{
    m_logger.debug("HookManager: Attempting AOB scan for mid hook '{}' with pattern: \"{}\", offset: {}.",
                   name, aob_pattern_str, DetourModKit::Format::format_hex(static_cast<int>(aob_offset), 0));

    auto pattern = parse_aob(aob_pattern_str);
    if (!pattern.has_value())
    {
        m_logger.error("HookManager: AOB pattern parsing failed for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    std::byte *found_address_start = find_pattern(reinterpret_cast<std::byte *>(module_base), module_size, pattern.value());
    if (!found_address_start)
    {
        m_logger.error("HookManager: AOB pattern not found for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger.info("HookManager: AOB pattern for mid hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
                  name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(found_address_start)),
                  DetourModKit::Format::format_hex(static_cast<int>(aob_offset), 0), DetourModKit::Format::format_address(target_address));

    return create_mid_hook(name, target_address, detour_function, config);
}

bool HookManager::remove_hook(const std::string &hook_id)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_hooks.find(hook_id);
    if (it != m_hooks.end())
    {
        std::string name_of_removed_hook = it->second->get_name();
        HookType type_of_removed_hook = it->second->get_type();
        m_hooks.erase(it);
        m_logger.info("HookManager: Hook '{}' of type '{}' has been removed and unhooked.",
                      name_of_removed_hook, (type_of_removed_hook == HookType::Inline ? "Inline" : "Mid"));
        return true;
    }
    m_logger.warning("HookManager: Attempted to remove hook with ID '{}', but it was not found.", hook_id);
    return false;
}

void HookManager::remove_all_hooks()
{
    m_shutdown_called = false;
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    if (!m_hooks.empty())
    {
        size_t num_hooks = m_hooks.size();
        m_logger.info("HookManager: Removing all {} managed hooks...", num_hooks);
        m_hooks.clear();
        m_logger.info("HookManager: All {} managed hooks have been removed and unhooked.", num_hooks);
    }
    else
    {
        m_logger.debug("HookManager: remove_all_hooks called, but no hooks were active to remove.");
    }
}

bool HookManager::enable_hook(const std::string &hook_id)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_hooks.find(hook_id);
    if (it != m_hooks.end())
    {
        Hook *hook = it->second.get();
        if (hook->get_status() == HookStatus::Disabled)
        {
            if (hook->enable())
            {
                m_logger.info("HookManager: Hook '{}' successfully enabled.", hook_id);
                return true;
            }
            else
            {
                m_logger.error("HookManager: Failed to enable hook '{}'. Underlying SafetyHook call may have failed.", hook_id);
                return false;
            }
        }
        else if (hook->get_status() == HookStatus::Active)
        {
            m_logger.debug("HookManager: Hook '{}' is already active. Enable request ignored.", hook_id);
            return true;
        }
        else
        {
            m_logger.warning("HookManager: Hook '{}' cannot be enabled. Current status: {}", hook_id, Hook::status_to_string(hook->get_status()));
            return false;
        }
    }
    m_logger.warning("HookManager: Hook ID '{}' not found for enable operation.", hook_id);
    return false;
}

bool HookManager::disable_hook(const std::string &hook_id)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_hooks.find(hook_id);
    if (it != m_hooks.end())
    {
        Hook *hook = it->second.get();
        if (hook->get_status() == HookStatus::Active)
        {
            if (hook->disable())
            {
                m_logger.info("HookManager: Hook '{}' successfully disabled.", hook_id);
                return true;
            }
            else
            {
                m_logger.error("HookManager: Failed to disable hook '{}'. Underlying SafetyHook call may have failed.", hook_id);
                return false;
            }
        }
        else if (hook->get_status() == HookStatus::Disabled)
        {
            m_logger.debug("HookManager: Hook '{}' is already disabled. Disable request ignored.", hook_id);
            return true;
        }
        else
        {
            m_logger.warning("HookManager: Hook '{}' cannot be disabled. Current status: {}", hook_id, Hook::status_to_string(hook->get_status()));
            return false;
        }
    }
    m_logger.warning("HookManager: Hook ID '{}' not found for disable operation.", hook_id);
    return false;
}

std::optional<HookStatus> HookManager::get_hook_status(const std::string &hook_id) const
{
    std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_hooks.find(hook_id);
    if (it != m_hooks.end())
    {
        return it->second->get_status();
    }
    return std::nullopt;
}

std::unordered_map<HookStatus, size_t> HookManager::get_hook_counts() const
{
    std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
    std::unordered_map<HookStatus, size_t> counts;
    counts[HookStatus::Active] = 0;
    counts[HookStatus::Disabled] = 0;
    counts[HookStatus::Failed] = 0;
    counts[HookStatus::Removed] = 0;
    for (const auto &[name, hook_ptr] : m_hooks)
    {
        counts[hook_ptr->get_status()]++;
    }
    return counts;
}

std::vector<std::string> HookManager::get_hook_ids(std::optional<HookStatus> status_filter) const
{
    std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
    std::vector<std::string> ids;
    ids.reserve(m_hooks.size());
    for (const auto &[name, hook_ptr] : m_hooks)
    {
        if (!status_filter.has_value() || hook_ptr->get_status() == status_filter.value())
        {
            ids.push_back(name);
        }
    }
    return ids;
}

// get_inline_hook and get_mid_hook replaced by with_inline_hook / with_mid_hook
// (template methods defined in hook_manager.hpp)
