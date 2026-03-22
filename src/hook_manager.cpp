#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/format.hpp"

#include <algorithm>
#include <cstddef>
#include <format>

using namespace DetourModKit;
using namespace DetourModKit::Scanner;

namespace
{
    struct DeferredLog
    {
        std::string msg;
        LogLevel level;
    };
} // anonymous namespace

HookManager &HookManager::get_instance()
{
    static HookManager instance;
    return instance;
}

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

HookManager::~HookManager() noexcept
{
    if (!m_shutdown_called.load(std::memory_order_acquire))
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
        for (auto &[name, hook] : m_hooks)
        {
            hook->disable();
        }
        m_hooks.clear();
    }
}

void HookManager::shutdown()
{
    bool expected = false;
    if (!m_shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    for (auto &[name, hook] : m_hooks)
    {
        hook->disable();
    }
    m_hooks.clear();
}

std::string HookManager::error_to_string(const safetyhook::InlineHook::Error &err) const
{
    const int type_int = static_cast<int>(err.type);
    const auto ip_str = DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(err.ip));

    switch (err.type)
    {
    case safetyhook::InlineHook::Error::BAD_ALLOCATION:
        return std::format("SafetyHook InlineHook Error (Type: {}): Bad allocation (Allocator error: {})",
                           type_int, static_cast<int>(err.allocator_error));
    case safetyhook::InlineHook::Error::FAILED_TO_DECODE_INSTRUCTION:
        return std::format("SafetyHook InlineHook Error (Type: {}): Failed to decode instruction at address {}",
                           type_int, ip_str);
    case safetyhook::InlineHook::Error::SHORT_JUMP_IN_TRAMPOLINE:
        return std::format("SafetyHook InlineHook Error (Type: {}): Short jump found in trampoline at address {}",
                           type_int, ip_str);
    case safetyhook::InlineHook::Error::IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE:
        return std::format("SafetyHook InlineHook Error (Type: {}): IP-relative instruction out of range at address {}",
                           type_int, ip_str);
    case safetyhook::InlineHook::Error::UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE:
        return std::format("SafetyHook InlineHook Error (Type: {}): Unsupported instruction in trampoline at address {}",
                           type_int, ip_str);
    case safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT:
        return std::format("SafetyHook InlineHook Error (Type: {}): Failed to unprotect memory at address {}",
                           type_int, ip_str);
    case safetyhook::InlineHook::Error::NOT_ENOUGH_SPACE:
        return std::format("SafetyHook InlineHook Error (Type: {}): Not enough space for the hook (prologue too short) at address {}",
                           type_int, ip_str);
    default:
        return std::format("SafetyHook InlineHook Error (Type: {}): Unknown error type", type_int);
    }
}

std::string HookManager::error_to_string(const safetyhook::MidHook::Error &err) const
{
    const int type_int = static_cast<int>(err.type);

    switch (err.type)
    {
    case safetyhook::MidHook::Error::BAD_ALLOCATION:
        return std::format("SafetyHook MidHook Error (Type: {}): Bad allocation (Allocator error: {})",
                           type_int, static_cast<int>(err.allocator_error));
    case safetyhook::MidHook::Error::BAD_INLINE_HOOK:
        return std::format("SafetyHook MidHook Error (Type: {}): Bad underlying inline hook. Details: {}",
                           type_int, error_to_string(err.inline_hook_error));
    default:
        return std::format("SafetyHook MidHook Error (Type: {}): Unknown error type", type_int);
    }
}

// Non-locking internal helpers - caller must hold m_hooks_mutex
bool HookManager::hook_id_exists_locked(const std::string &hook_id) const
{
    return m_hooks.find(hook_id) != m_hooks.end();
}

std::expected<std::string, HookError> HookManager::create_inline_hook(
    const std::string &name,
    uintptr_t target_address,
    void *detour_function,
    void **original_trampoline,
    const HookConfig &config)
{
    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLog>>
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

        if (!m_allocator)
        {
            return {std::unexpected(HookError::AllocatorNotAvailable),
                    {{std::format("HookManager: Allocator not available. Cannot create inline hook '{}'.", name), LogLevel::Error}}};
        }
        if (target_address == 0)
        {
            return {std::unexpected(HookError::InvalidTargetAddress),
                    {{std::format("HookManager: Target address is NULL for inline hook '{}'.", name), LogLevel::Error}}};
        }
        if (detour_function == nullptr)
        {
            return {std::unexpected(HookError::InvalidDetourFunction),
                    {{std::format("HookManager: Detour function is NULL for inline hook '{}'.", name), LogLevel::Error}}};
        }
        if (original_trampoline == nullptr)
        {
            return {std::unexpected(HookError::InvalidTrampolinePointer),
                    {{std::format("HookManager: Original trampoline pointer (output) is NULL for inline hook '{}'.", name), LogLevel::Error}}};
        }
        *original_trampoline = nullptr;

        if (hook_id_exists_locked(name))
        {
            return {std::unexpected(HookError::HookAlreadyExists),
                    {{std::format("HookManager: A hook with the name '{}' already exists.", name), LogLevel::Error}}};
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
                return {std::unexpected(HookError::SafetyHookError),
                        {{std::format("HookManager: Failed to create SafetyHook::InlineHook for '{}' at {}. Error: {}",
                                      name, DetourModKit::Format::format_address(target_address), error_to_string(hook_creation_result.error())),
                          LogLevel::Error}}};
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
            }

            auto managed_hook = std::make_unique<InlineHook>(name, target_address, std::move(sh_inline_hook_ptr), initial_status);
            m_hooks.emplace(name, std::move(managed_hook));

            std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : " (created disabled)";
            std::vector<DeferredLog> logs;
            logs.push_back({std::format("HookManager: Successfully created {} inline hook '{}' targeting {}.",
                                        status_message, name, DetourModKit::Format::format_address(target_address)),
                            LogLevel::Info});

            if (initial_status == HookStatus::Disabled && config.auto_enable)
            {
                logs.push_back({std::format("HookManager: Inline hook '{}' was configured for auto-enable but is currently disabled post-creation.", name),
                                LogLevel::Warning});
            }

            return {name, std::move(logs)};
        }
        catch (const std::exception &e)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: An std::exception occurred during inline hook creation for '{}': {}", name, e.what()),
                      LogLevel::Error}}};
        }
        catch (...)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: An unknown exception occurred during inline hook creation for '{}'.", name),
                      LogLevel::Error}}};
        }
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
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
                   name, aob_pattern_str, DetourModKit::Format::format_hex(aob_offset));

    auto pattern = parse_aob(aob_pattern_str);
    if (!pattern.has_value())
    {
        m_logger.error("HookManager: AOB pattern parsing failed for inline hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    const std::byte *found_address_start = find_pattern(reinterpret_cast<const std::byte *>(module_base), module_size, pattern.value());
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
                  DetourModKit::Format::format_hex(aob_offset), DetourModKit::Format::format_address(target_address));

    return create_inline_hook(name, target_address, detour_function, original_trampoline, config);
}

std::expected<std::string, HookError> HookManager::create_mid_hook(
    const std::string &name,
    uintptr_t target_address,
    safetyhook::MidHookFn detour_function,
    const HookConfig &config)
{
    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLog>>
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

        if (!m_allocator)
        {
            return {std::unexpected(HookError::AllocatorNotAvailable),
                    {{std::format("HookManager: Allocator not available. Cannot create mid hook '{}'.", name), LogLevel::Error}}};
        }
        if (target_address == 0)
        {
            return {std::unexpected(HookError::InvalidTargetAddress),
                    {{std::format("HookManager: Target address is NULL for mid hook '{}'.", name), LogLevel::Error}}};
        }
        if (detour_function == nullptr)
        {
            return {std::unexpected(HookError::InvalidDetourFunction),
                    {{std::format("HookManager: Detour function is NULL for mid hook '{}'.", name), LogLevel::Error}}};
        }

        if (hook_id_exists_locked(name))
        {
            return {std::unexpected(HookError::HookAlreadyExists),
                    {{std::format("HookManager: A hook with the name '{}' already exists.", name), LogLevel::Error}}};
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
                return {std::unexpected(HookError::SafetyHookError),
                        {{std::format("HookManager: Failed to create SafetyHook::MidHook for '{}' at {}. Error: {}",
                                      name, DetourModKit::Format::format_address(target_address), error_to_string(hook_creation_result.error())),
                          LogLevel::Error}}};
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
            }

            auto managed_hook = std::make_unique<MidHook>(name, target_address, std::move(sh_mid_hook_ptr), initial_status);
            m_hooks.emplace(name, std::move(managed_hook));

            std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : " (created disabled)";
            std::vector<DeferredLog> logs;
            logs.push_back({std::format("HookManager: Successfully created {} mid hook '{}' targeting {}.",
                                        status_message, name, DetourModKit::Format::format_address(target_address)),
                            LogLevel::Info});

            if (initial_status == HookStatus::Disabled && config.auto_enable)
            {
                logs.push_back({std::format("HookManager: Mid hook '{}' was configured for auto-enable but is currently disabled post-creation.", name),
                                LogLevel::Warning});
            }

            return {name, std::move(logs)};
        }
        catch (const std::exception &e)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: An std::exception occurred during mid hook creation for '{}': {}", name, e.what()),
                      LogLevel::Error}}};
        }
        catch (...)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: An unknown exception occurred during mid hook creation for '{}'.", name),
                      LogLevel::Error}}};
        }
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
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
                   name, aob_pattern_str, DetourModKit::Format::format_hex(aob_offset));

    auto pattern = parse_aob(aob_pattern_str);
    if (!pattern.has_value())
    {
        m_logger.error("HookManager: AOB pattern parsing failed for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    const std::byte *found_address_start = find_pattern(reinterpret_cast<const std::byte *>(module_base), module_size, pattern.value());
    if (!found_address_start)
    {
        m_logger.error("HookManager: AOB pattern not found for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger.info("HookManager: AOB pattern for mid hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
                  name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(found_address_start)),
                  DetourModKit::Format::format_hex(aob_offset), DetourModKit::Format::format_address(target_address));

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

    // Reset shutdown flag to allow reuse after a full reset.
    // Safe because all hooks have been cleared — no double-free risk.
    m_shutdown_called.store(false, std::memory_order_release);
}

bool HookManager::enable_hook(const std::string &hook_id)
{
    std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_hooks.find(hook_id);
    if (it == m_hooks.end())
    {
        m_logger.warning("HookManager: Hook ID '{}' not found for enable operation.", hook_id);
        return false;
    }

    Hook *hook = it->second.get();
    if (hook->enable())
    {
        m_logger.info("HookManager: Hook '{}' successfully enabled.", hook_id);
        return true;
    }

    const auto status = hook->get_status();
    if (status == HookStatus::Active)
    {
        m_logger.debug("HookManager: Hook '{}' is already active. Enable request ignored.", hook_id);
        return true;
    }

    if (status == HookStatus::Disabled)
    {
        m_logger.error("HookManager: Failed to enable hook '{}'. Underlying SafetyHook call may have failed.", hook_id);
    }
    else
    {
        m_logger.warning("HookManager: Hook '{}' cannot be enabled. Current status: {}", hook_id, Hook::status_to_string(status));
    }
    return false;
}

bool HookManager::disable_hook(const std::string &hook_id)
{
    std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_hooks.find(hook_id);
    if (it == m_hooks.end())
    {
        m_logger.warning("HookManager: Hook ID '{}' not found for disable operation.", hook_id);
        return false;
    }

    Hook *hook = it->second.get();
    if (hook->disable())
    {
        m_logger.info("HookManager: Hook '{}' successfully disabled.", hook_id);
        return true;
    }

    const auto status = hook->get_status();
    if (status == HookStatus::Disabled)
    {
        m_logger.debug("HookManager: Hook '{}' is already disabled. Disable request ignored.", hook_id);
        return true;
    }

    if (status == HookStatus::Active)
    {
        m_logger.error("HookManager: Failed to disable hook '{}'. Underlying SafetyHook call may have failed.", hook_id);
    }
    else
    {
        m_logger.warning("HookManager: Hook '{}' cannot be disabled. Current status: {}", hook_id, Hook::status_to_string(status));
    }
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
