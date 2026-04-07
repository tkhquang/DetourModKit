#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/format.hpp"

#include <algorithm>
#include <cstddef>
#include <format>

using namespace DetourModKit;
using namespace DetourModKit::Scanner;


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
        // Disable hooks before acquiring the exclusive lock to avoid deadlock.
        // A hooked thread blocked on m_hooks_mutex (e.g. via with_inline_hook)
        // cannot drain from SafetyHook::disable() if we hold the lock first.
        {
            std::shared_lock<std::shared_mutex> shared(m_hooks_mutex);
            for (auto &[name, hook] : m_hooks)
            {
                (void)hook->disable();
            }
        }
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
        m_vmt_hooks.clear();
        m_hooks.clear();
    }
}

void HookManager::shutdown()
{
    bool expected = false;
    if (!m_shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    // Two-phase shutdown: disable hooks under a shared lock first so that
    // hooked threads blocked on m_hooks_mutex can drain from SafetyHook's
    // disable() without deadlock, then clear the maps under exclusive lock.
    {
        std::shared_lock<std::shared_mutex> shared(m_hooks_mutex);
        for (auto &[name, hook] : m_hooks)
        {
            (void)hook->disable();
        }
    }
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
        m_vmt_hooks.clear();
        m_hooks.clear();

        // Reset under the lock so concurrent create_*_hook calls cannot
        // observe the flag as true (rejected) and then immediately see it
        // as false (accepted) before the map is fully cleared.
        //
        // This intentionally allows reuse after shutdown (hot-reload).
        // The exclusive lock serializes the entire clear-and-reset sequence,
        // so there is no window where a concurrent create_*_hook can slip
        // through against a half-cleared map. Making shutdown permanent
        // would break the documented hot-reload workflow without adding
        // safety, since callers that destroy detour functions after shutdown
        // have a caller-side lifetime bug regardless of the flag state.
        m_shutdown_called.store(false, std::memory_order_release);
    }
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

std::expected<std::string, HookError> HookManager::create_inline_hook(
    std::string_view name,
    uintptr_t target_address,
    void *detour_function,
    void **original_trampoline,
    const HookConfig &config)
{
    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLogEntry>>
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot create inline hook '{}'.", name), LogLevel::Error}}};
        }
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
            auto sh_flags = config.auto_enable
                                ? safetyhook::InlineHook::Default
                                : safetyhook::InlineHook::StartDisabled;

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

            auto sh_inline_hook = std::move(hook_creation_result.value());
            void *trampoline = sh_inline_hook.original<void *>();

            HookStatus initial_status = sh_inline_hook.enabled() ? HookStatus::Active : HookStatus::Disabled;

            // Pre-build log entries before committing to m_hooks so that
            // allocation failures in std::format cannot leave a ghost hook.
            std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : "(disabled)";
            std::vector<DeferredLogEntry> logs;
            logs.reserve(2);
            logs.push_back({std::format("HookManager: Successfully created {} inline hook '{}' targeting {}.",
                                        status_message, name, DetourModKit::Format::format_address(target_address)),
                            LogLevel::Info});

            if (initial_status == HookStatus::Disabled && config.auto_enable)
            {
                logs.push_back({std::format("HookManager: Inline hook '{}' was configured for auto-enable but is currently disabled post-creation.", name),
                                LogLevel::Warning});
            }

            std::string name_str{name};
            auto managed_hook = std::make_unique<InlineHook>(name_str, target_address, std::move(sh_inline_hook), initial_status);
            m_hooks.emplace(name_str, std::move(managed_hook));
            *original_trampoline = trampoline;

            return {std::move(name_str), std::move(logs)};
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
    std::string_view name,
    uintptr_t module_base,
    size_t module_size,
    std::string_view aob_pattern_str,
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
    std::string_view name,
    uintptr_t target_address,
    safetyhook::MidHookFn detour_function,
    const HookConfig &config)
{
    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLogEntry>>
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot create mid hook '{}'.", name), LogLevel::Error}}};
        }
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
            auto sh_flags = config.auto_enable
                                ? safetyhook::MidHook::Default
                                : safetyhook::MidHook::StartDisabled;

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

            auto sh_mid_hook = std::move(hook_creation_result.value());

            HookStatus initial_status = sh_mid_hook.enabled() ? HookStatus::Active : HookStatus::Disabled;

            // Pre-build log entries before committing to m_hooks so that
            // allocation failures in std::format cannot leave a ghost hook.
            std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : "(disabled)";
            std::vector<DeferredLogEntry> logs;
            logs.reserve(2);
            logs.push_back({std::format("HookManager: Successfully created {} mid hook '{}' targeting {}.",
                                        status_message, name, DetourModKit::Format::format_address(target_address)),
                            LogLevel::Info});

            if (initial_status == HookStatus::Disabled && config.auto_enable)
            {
                logs.push_back({std::format("HookManager: Mid hook '{}' was configured for auto-enable but is currently disabled post-creation.", name),
                                LogLevel::Warning});
            }

            std::string name_str{name};
            auto managed_hook = std::make_unique<MidHook>(name_str, target_address, std::move(sh_mid_hook), initial_status);
            m_hooks.emplace(name_str, std::move(managed_hook));

            return {std::move(name_str), std::move(logs)};
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
    std::string_view name,
    uintptr_t module_base,
    size_t module_size,
    std::string_view aob_pattern_str,
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

bool HookManager::remove_hook(std::string_view hook_id)
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

    size_t num_vmt = m_vmt_hooks.size();
    if (num_vmt > 0)
    {
        m_logger.info("HookManager: Removing all {} VMT hooks...", num_vmt);
        m_vmt_hooks.clear();
    }

    if (!m_hooks.empty())
    {
        size_t num_hooks = m_hooks.size();
        m_logger.info("HookManager: Removing all {} managed hooks...", num_hooks);
        m_hooks.clear();
        m_logger.info("HookManager: All {} managed hooks have been removed and unhooked.", num_hooks);
    }
    else if (num_vmt == 0)
    {
        m_logger.debug("HookManager: remove_all_hooks called, but no hooks were active to remove.");
    }

    // Both shutdown() and remove_all_hooks() reset m_shutdown_called to false
    // under the exclusive lock, allowing subsequent create_*_hook() calls to
    // succeed. See the comment in shutdown() for the serialization rationale.
    m_shutdown_called.store(false, std::memory_order_release);
}

bool HookManager::enable_hook(std::string_view hook_id)
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

bool HookManager::disable_hook(std::string_view hook_id)
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

std::optional<HookStatus> HookManager::get_hook_status(std::string_view hook_id) const
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

std::expected<std::string, HookError> HookManager::create_vmt_hook(
    std::string_view name, void *object)
{
    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLogEntry>>
    {
        std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);

        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot create VMT hook '{}'.", name), LogLevel::Error}}};
        }
        if (object == nullptr)
        {
            return {std::unexpected(HookError::InvalidObject),
                    {{std::format("HookManager: Object pointer is NULL for VMT hook '{}'.", name), LogLevel::Error}}};
        }
        if (vmt_hook_exists_locked(name))
        {
            return {std::unexpected(HookError::HookAlreadyExists),
                    {{std::format("HookManager: A VMT hook with the name '{}' already exists.", name), LogLevel::Error}}};
        }

        try
        {
            auto vmt_result = safetyhook::VmtHook::create(object);

            if (!vmt_result)
            {
                return {std::unexpected(HookError::SafetyHookError),
                        {{std::format("HookManager: Failed to create SafetyHook::VmtHook for '{}' on object {}.",
                                      name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                          LogLevel::Error}}};
            }

            std::string name_str{name};

            std::vector<DeferredLogEntry> logs;
            logs.push_back({std::format("HookManager: Successfully created VMT hook '{}' on object {}.",
                                        name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                            LogLevel::Info});

            m_vmt_hooks.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(name_str),
                std::forward_as_tuple(name_str, std::move(vmt_result.value())));

            return {std::move(name_str), std::move(logs)};
        }
        catch (const std::exception &e)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: Exception during VMT hook creation for '{}': {}", name, e.what()),
                      LogLevel::Error}}};
        }
        catch (...)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: Unknown exception during VMT hook creation for '{}'.", name),
                      LogLevel::Error}}};
        }
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

bool HookManager::remove_vmt_hook(std::string_view vmt_name)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_vmt_hooks.find(vmt_name);
    if (it != m_vmt_hooks.end())
    {
        std::string removed_name = it->second.get_name();
        m_vmt_hooks.erase(it);
        m_logger.info("HookManager: VMT hook '{}' has been removed.", removed_name);
        return true;
    }
    m_logger.warning("HookManager: Attempted to remove VMT hook '{}', but it was not found.", vmt_name);
    return false;
}

bool HookManager::remove_vmt_method(std::string_view vmt_name, size_t method_index)
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_vmt_hooks.find(vmt_name);
    if (it == m_vmt_hooks.end())
    {
        m_logger.warning("HookManager: VMT hook '{}' not found for method removal.", vmt_name);
        return false;
    }

    if (it->second.remove_method_hook(method_index))
    {
        m_logger.info("HookManager: VMT '{}' method index {} has been unhooked.", vmt_name, method_index);
        return true;
    }

    m_logger.warning("HookManager: VMT '{}' has no hooked method at index {}.", vmt_name, method_index);
    return false;
}

bool HookManager::apply_vmt_hook(std::string_view vmt_name, void *object)
{
    if (object == nullptr)
    {
        m_logger.warning("HookManager: Cannot apply VMT hook '{}' to null object.", vmt_name);
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_vmt_hooks.find(vmt_name);
    if (it == m_vmt_hooks.end())
    {
        m_logger.warning("HookManager: VMT hook '{}' not found for apply.", vmt_name);
        return false;
    }

    it->second.vmt_hook().apply(object);
    m_logger.info("HookManager: VMT hook '{}' applied to object {}.",
                  vmt_name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)));
    return true;
}

bool HookManager::remove_vmt_from_object(std::string_view vmt_name, void *object)
{
    if (object == nullptr)
    {
        m_logger.warning("HookManager: Cannot remove VMT hook '{}' from null object.", vmt_name);
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    auto it = m_vmt_hooks.find(vmt_name);
    if (it == m_vmt_hooks.end())
    {
        m_logger.warning("HookManager: VMT hook '{}' not found for object removal.", vmt_name);
        return false;
    }

    it->second.vmt_hook().remove(object);
    m_logger.info("HookManager: VMT hook '{}' removed from object {}.",
                  vmt_name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)));
    return true;
}

void HookManager::remove_all_vmt_hooks()
{
    std::unique_lock<std::shared_mutex> lock(m_hooks_mutex);
    if (!m_vmt_hooks.empty())
    {
        size_t num_hooks = m_vmt_hooks.size();
        m_logger.info("HookManager: Removing all {} VMT hooks...", num_hooks);
        m_vmt_hooks.clear();
        m_logger.info("HookManager: All {} VMT hooks have been removed.", num_hooks);
    }
    else
    {
        m_logger.debug("HookManager: remove_all_vmt_hooks called, but no VMT hooks were active.");
    }
}

std::vector<std::string> HookManager::get_vmt_hook_names() const
{
    std::shared_lock<std::shared_mutex> lock(m_hooks_mutex);
    std::vector<std::string> names;
    names.reserve(m_vmt_hooks.size());
    for (const auto &[name, entry] : m_vmt_hooks)
    {
        names.push_back(name);
    }
    return names;
}
