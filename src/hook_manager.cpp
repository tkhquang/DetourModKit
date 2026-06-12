#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/memory.hpp"
#include "platform.hpp"
#include "x86_decode.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <new>
#include <optional>
#include <vector>

using namespace DetourModKit;
using DetourModKit::Scanner::parse_aob;

namespace
{
    enum class PrehookState
    {
        NotHooked,
        HookedBySameModule,
        HookedByOtherModule
    };

    struct PrehookDetection
    {
        PrehookState state{PrehookState::NotHooked};
        std::uintptr_t jmp_destination{0};
    };

    std::optional<std::uintptr_t> decode_prehook_destination(std::uintptr_t target_address) noexcept
    {
        // Read the opcode bytes under a fault guard and dispatch on the copy;
        // an unguarded dereference of target_address could fault if the page is unmapped or guarded.
        std::array<std::uint8_t, 2> opcode{};
        if (!Memory::seh_read_bytes(target_address, opcode.data(), opcode.size()))
        {
            return std::nullopt;
        }

        // Only E9 (jmp rel32) and FF 25 (jmp [rip+disp32]) can redirect a prologue into a hook trampoline in another
        // module. EB (jmp rel8) reaches at most +/-127 bytes, far too short to land in a foreign hook stub, so a
        // leading 0xEB is ordinary code, not a pre-existing inline hook. Matching it here would only add false
        // positives on functions that legitimately begin with a short jump.
        if (opcode[0] == 0xE9)
        {
            return detail::decode_e9_rel32(target_address);
        }

        if (opcode[0] == 0xFF && opcode[1] == 0x25)
        {
            return detail::decode_ff25_indirect(target_address);
        }

        return std::nullopt;
    }

    PrehookDetection detect_existing_inline_hook(std::uintptr_t target_address) noexcept
    {
        PrehookDetection result;
        if (target_address == 0)
        {
            return result;
        }

        const auto destination_opt = decode_prehook_destination(target_address);
        if (!destination_opt)
        {
            return result;
        }
        const auto destination = *destination_opt;
        result.jmp_destination = destination;

        HMODULE target_module = nullptr;
        HMODULE dest_module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(target_address), &target_module))
        {
            target_module = nullptr;
        }
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(destination), &dest_module))
        {
            dest_module = nullptr;
        }

        if (dest_module != nullptr && target_module == dest_module)
        {
            result.state = PrehookState::HookedBySameModule;
        }
        else
        {
            result.state = PrehookState::HookedByOtherModule;
        }
        return result;
    }
} // anonymous namespace

HookManager &HookManager::get_instance()
{
    static HookManager instance;
    return instance;
}

HookManager::HookManager(Logger &logger) : m_logger(logger)
{
    m_allocator = safetyhook::Allocator::global();
    if (!m_allocator)
    {
        m_logger.error("HookManager: Failed to get SafetyHook global allocator! Hook creation will fail.");
    }
    else
    {
        m_logger.debug("HookManager: SafetyHook global allocator obtained.");
    }
    m_logger.debug("HookManager: Initialized.");
}

HookManager::~HookManager() noexcept
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        return;
    }

    // Fallback teardown path. Reached only when the process did not call
    // DMK_Shutdown() / HookManager::shutdown() before static destruction (abnormal exit, FreeLibrary race, host crash).
    //
    // Ordering (matches the shutdown() contract so readers see one story):
    //   1. Flip m_shutdown_called under m_mutator_gate (exclusive) to
    //      block new mutators and serialize with a late shutdown() call.
    //   2. Disable all hooks under shared m_hooks_mutex. SafetyHook::disable()
    //      restores the original bytes and relocates any thread caught inside
    //      the patched prologue (thread-suspend + IP fixup); it does NOT drain
    //      a thread already in the detour or trampoline body. The shared lock
    //      just lets the kit's own with_* readers coexist with the disable.
    //   3. Acquire exclusive m_hooks_mutex to wait out any shared_lock
    //      holder still inside a with_* callback. Only then clear the
    //      maps -- destroying the Hook objects would UAF a live reader.
    //
    // Loader-lock fallback: if the destructor is fired with the OS loader lock held (e.g. during abnormal DLL unload),
    // acquiring m_mutator_gate or blocking readers can deadlock against another thread waiting on a loader callback.
    // Leak the maps in that case; the pinned module keeps the hooks' code pages live so SafetyHook trampolines do not
    // dangle. Mirrors the pattern used in Logger::shutdown_internal().
    if (detail::is_loader_lock_held())
    {
        detail::pin_current_module();
        // Intentional leak under loader lock: draining readers or destroying
        // Hook / VmtHookEntry values here can deadlock against another thread waiting on a loader callback. The pinned
        // module keeps the SafetyHook trampoline pages live for the remainder of the process, so the leaked maps and
        // their contents stay valid storage even though no one will ever observe them again. HookManager is a singleton
        // so this branch runs at most once per process.
        //
        // Heap-allocate each map directly rather than nesting them inside an outer container. A container of containers
        // would force the standard library to instantiate a copy-construction fallback for the element type whenever
        // the element's move constructor is not unconditionally noexcept, and that copy path would try to copy a
        // move-only member (VmtHookEntry owns a safetyhook::VmtHook).
        //
        // Default-construct each map on the heap, then swap content in. std::unordered_map's move constructor is not
        // guaranteed noexcept on every standard library implementation (some mark it noexcept(false) so
        // allocator-propagation fallbacks can allocate); invoking it from a noexcept destructor would risk
        // std::terminate on an unexpected allocator fallback. With a default std::allocator (stateless,
        // is_always_equal) and noexcept hasher / comparator, member swap() is specified noexcept and performs an O(1)
        // pointer swap that allocates nothing, so it is safe to call from a noexcept context. On allocation failure the
        // new (std::nothrow) expression returns nullptr, the source maps keep their contents, and control falls through
        // to the normal ~HookManager member destruction epilogue. That epilogue is best-effort under loader lock, but
        // the pinned module still keeps trampoline code pages live so straggler trampoline calls land on valid memory.
        auto *leaked_hooks = new (std::nothrow) detail::HookMap();
        auto *leaked_vmt_hooks = new (std::nothrow) detail::VmtHookMap();
        if (leaked_hooks != nullptr)
        {
            leaked_hooks->swap(m_hooks);
        }
        if (leaked_vmt_hooks != nullptr)
        {
            leaked_vmt_hooks->swap(m_vmt_hooks);
        }
        // Surface this loader-lock leak so consumers can observe teardown escape-hatch activity without parsing logs.
        DetourModKit::Diagnostics::record_intentional_leak(DetourModKit::Diagnostics::LeakSubsystem::HookManager);
        m_shutdown_called.store(true, std::memory_order_release);
        return;
    }

    std::unique_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
    m_shutdown_called.store(true, std::memory_order_release);

    {
        std::shared_lock<detail::SrwSharedMutex> shared(m_hooks_mutex);
        disable_hooks_reverse_order_locked();
    }

    std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
    clear_vmt_hooks_locked();
    clear_hooks_locked();
}

void HookManager::shutdown()
{
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant shutdown() from within a with_*/try_with_* callback rejected; defer "
                         "hook teardown until the callback returns.");
        return;
    }

    // Serialize with remove_all_hooks() via compare_exchange_strong. Only one teardown owner proceeds.
    bool expected = false;
    if (!m_shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    // Block all mutators (create_*_hook, enable, disable, remove) before entering phase 1. They hold shared on
    // m_mutator_gate, so acquiring exclusive here waits for active mutators and blocks new ones.
    std::unique_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);

    // Two-phase shutdown: disable hooks under a shared lock first, then clear the maps under the exclusive lock. The
    // shared phase lets the kit's own with_* readers (shared_lock holders) finish; SafetyHook::disable() relocates only
    // threads caught in the patched prologue and does not drain threads already in the detour or trampoline body, so
    // the caller must quiesce the hooked function during teardown to close the residual window.
    {
        std::shared_lock<detail::SrwSharedMutex> shared(m_hooks_mutex);
        disable_hooks_reverse_order_locked();
    }
    {
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        clear_vmt_hooks_locked();
        clear_hooks_locked();

        // Reset under the lock so concurrent create_*_hook calls cannot observe the flag as true (rejected) and then
        // immediately see it as false (accepted) before the map is fully cleared.
        //
        // This intentionally allows reuse after shutdown (hot-reload). The exclusive lock on m_mutator_gate serializes
        // the entire clear-and-reset sequence, so there is no window where a concurrent create_*_hook can slip through
        // against a half-cleared map. The mutator_gate exclusive lock is released here, allowing new mutators to
        // proceed with a fresh m_shutdown_called=false.
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
        return std::format("SafetyHook InlineHook Error (Type: {}): Bad allocation (Allocator error: {})", type_int,
                           static_cast<int>(err.allocator_error));
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
        return std::format(
            "SafetyHook InlineHook Error (Type: {}): Unsupported instruction in trampoline at address {}", type_int,
            ip_str);
    case safetyhook::InlineHook::Error::FAILED_TO_UNPROTECT:
        return std::format("SafetyHook InlineHook Error (Type: {}): Failed to unprotect memory at address {}", type_int,
                           ip_str);
    case safetyhook::InlineHook::Error::NOT_ENOUGH_SPACE:
        return std::format(
            "SafetyHook InlineHook Error (Type: {}): Not enough space for the hook (prologue too short) at address {}",
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
        return std::format("SafetyHook MidHook Error (Type: {}): Bad allocation (Allocator error: {})", type_int,
                           static_cast<int>(err.allocator_error));
    case safetyhook::MidHook::Error::BAD_INLINE_HOOK:
        return std::format("SafetyHook MidHook Error (Type: {}): Bad underlying inline hook. Details: {}", type_int,
                           error_to_string(err.inline_hook_error));
    default:
        return std::format("SafetyHook MidHook Error (Type: {}): Unknown error type", type_int);
    }
}

std::expected<std::string, HookError> HookManager::create_inline_hook(std::string_view name, uintptr_t target_address,
                                                                      void *detour_function, void **original_trampoline,
                                                                      const HookConfig &config)
{
    // Non-locking fast-fail: avoid acquiring mutator_gate when shutdown is already in progress.
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        if (original_trampoline)
            *original_trampoline = nullptr;
        m_logger.error("HookManager: Shutdown in progress. Cannot create inline hook '{}'.", name);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        if (original_trampoline)
            *original_trampoline = nullptr;
        m_logger.error("HookManager: Reentrant create_inline_hook('{}') from within a with_*/try_with_* callback "
                       "rejected; defer hook mutation until the callback returns.",
                       name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result,
          deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);

        // Re-check after acquiring locks (double-checked pattern).
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot create inline hook '{}'.", name),
                      LogLevel::Error}}};
        }
        if (!m_allocator)
        {
            return {std::unexpected(HookError::AllocatorNotAvailable),
                    {{std::format("HookManager: Allocator not available. Cannot create inline hook '{}'.", name),
                      LogLevel::Error}}};
        }
        if (target_address == 0)
        {
            return {
                std::unexpected(HookError::InvalidTargetAddress),
                {{std::format("HookManager: Target address is NULL for inline hook '{}'.", name), LogLevel::Error}}};
        }
        if (detour_function == nullptr)
        {
            return {
                std::unexpected(HookError::InvalidDetourFunction),
                {{std::format("HookManager: Detour function is NULL for inline hook '{}'.", name), LogLevel::Error}}};
        }
        if (original_trampoline == nullptr)
        {
            return {
                std::unexpected(HookError::InvalidTrampolinePointer),
                {{std::format("HookManager: Original trampoline pointer (output) is NULL for inline hook '{}'.", name),
                  LogLevel::Error}}};
        }
        *original_trampoline = nullptr;

        if (hook_id_exists_locked(name))
        {
            return {std::unexpected(HookError::HookAlreadyExists),
                    {{std::format("HookManager: A hook with the name '{}' already exists.", name), LogLevel::Error}}};
        }

        // Self-registry pre-flight: does this HookManager already patch this exact address? Layering a second managed
        // hook onto one target is the use-after-free-on-teardown hazard -- SafetyHook saves the live prologue (a jump
        // to the first detour) as the second hook's "original" bytes, so the two must unwind newest-first or the entry
        // is left jumping into a freed trampoline (see disable_hooks_reverse_order_locked). The registry check is
        // exact, unlike the prologue-byte heuristic below which cannot tell our own patch from a foreign module's.
        // Refuse under strict mode; otherwise record which managed hook is being layered on for the deferred warning.
        std::string layered_on_managed_hook;
        if (const std::string *self_owner = find_hook_owner_of_target_locked(target_address))
        {
            if (config.fail_if_already_hooked)
            {
                return {std::unexpected(HookError::TargetAlreadyHookedInProcess),
                        {{std::format("HookManager: Target {} for inline hook '{}' is already hooked by managed hook "
                                      "'{}'. Aborting under strict mode.",
                                      DetourModKit::Format::format_address(target_address), name, *self_owner),
                          LogLevel::Error}}};
            }
            layered_on_managed_hook = *self_owner;
        }

        // Foreign-module pre-flight: only meaningful when this manager does not already own a hook here. When it does,
        // the prologue jump is our own patch (handled above) and decoding it would misreport it as another module's.
        PrehookDetection prehook;
        if (layered_on_managed_hook.empty())
        {
            prehook = detect_existing_inline_hook(target_address);
            if (prehook.state == PrehookState::HookedByOtherModule && config.fail_if_already_hooked)
            {
                return {std::unexpected(HookError::TargetAlreadyHookedInProcess),
                        {{std::format(
                              "HookManager: Target {} for inline hook '{}' is already inline-hooked by another module "
                              "(JMP -> {}). Aborting under strict mode.",
                              DetourModKit::Format::format_address(target_address), name,
                              DetourModKit::Format::format_address(prehook.jmp_destination)),
                          LogLevel::Error}}};
            }
        }

        try
        {
            auto sh_flags =
                config.auto_enable ? safetyhook::InlineHook::Default : safetyhook::InlineHook::StartDisabled;

            auto hook_creation_result = safetyhook::InlineHook::create(
                m_allocator, reinterpret_cast<void *>(target_address), detour_function, sh_flags);

            if (!hook_creation_result)
            {
                return {std::unexpected(HookError::SafetyHookError),
                        {{std::format("HookManager: Failed to create SafetyHook::InlineHook for '{}' at {}. Error: {}",
                                      name, DetourModKit::Format::format_address(target_address),
                                      error_to_string(hook_creation_result.error())),
                          LogLevel::Error}}};
            }

            auto sh_inline_hook = std::move(hook_creation_result.value());
            void *trampoline = sh_inline_hook.original<void *>();

            HookStatus initial_status = sh_inline_hook.enabled() ? HookStatus::Active : HookStatus::Disabled;

            // Pre-build log entries before committing to m_hooks so that allocation failures in std::format cannot
            // leave a ghost hook.
            std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : "(disabled)";
            std::vector<DeferredLogEntry> logs;
            logs.reserve(3);
            logs.push_back({std::format("HookManager: Successfully created {} inline hook '{}' targeting {}.",
                                        status_message, name, DetourModKit::Format::format_address(target_address)),
                            LogLevel::Info});

            if (!layered_on_managed_hook.empty())
            {
                logs.push_back(
                    {std::format("HookManager: Target {} for inline hook '{}' is already hooked by managed hook '{}'; "
                                 "SafetyHook layered on top. Remove layered hooks newest-first.",
                                 DetourModKit::Format::format_address(target_address), name, layered_on_managed_hook),
                     LogLevel::Warning});
            }
            else if (prehook.state == PrehookState::HookedByOtherModule)
            {
                logs.push_back(
                    {std::format(
                         "HookManager: Target {} for inline hook '{}' was already inline-hooked by another module "
                         "(JMP -> {}); SafetyHook layered on top.",
                         DetourModKit::Format::format_address(target_address), name,
                         DetourModKit::Format::format_address(prehook.jmp_destination)),
                     LogLevel::Warning});
            }

            if (initial_status == HookStatus::Disabled && config.auto_enable)
            {
                logs.push_back({std::format("HookManager: Inline hook '{}' was configured for auto-enable "
                                            "but is currently disabled post-creation.",
                                            name),
                                LogLevel::Warning});
            }

            std::string name_str{name};
            auto managed_hook =
                std::make_unique<InlineHook>(name_str, target_address, std::move(sh_inline_hook), initial_status);
            // Record creation order before emplace: if emplace throws, the stale order entry is a harmless skip at
            // teardown, whereas a registered hook missing from the order vector would dodge the ordered unwind.
            m_hook_creation_order.push_back(name_str);
            m_hooks.emplace(name_str, std::move(managed_hook));
            *original_trampoline = trampoline;

            return {std::move(name_str), std::move(logs)};
        }
        catch (const std::exception &e)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: An std::exception occurred during inline hook creation for '{}': {}",
                                  name, e.what()),
                      LogLevel::Error}}};
        }
        catch (...)
        {
            return {
                std::unexpected(HookError::UnknownError),
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

std::expected<std::string, HookError>
HookManager::create_inline_hook_aob(std::string_view name, uintptr_t module_base, size_t module_size,
                                    std::string_view aob_pattern_str, ptrdiff_t aob_offset, void *detour_function,
                                    void **original_trampoline, const HookConfig &config)
{
    if (get_reentrancy_guard() > 0)
    {
        if (original_trampoline)
            *original_trampoline = nullptr;
        m_logger.error("HookManager: Reentrant create_inline_hook_aob('{}') from within a with_*/try_with_* callback "
                       "rejected; defer hook mutation until the callback returns.",
                       name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    m_logger.debug("HookManager: Attempting AOB scan for inline hook '{}' with pattern: \"{}\", offset: {}.", name,
                   aob_pattern_str, DetourModKit::Format::format_hex(aob_offset));

    auto pattern = parse_aob(aob_pattern_str);
    if (!pattern.has_value())
    {
        m_logger.error("HookManager: AOB pattern parsing failed for inline hook '{}'. Pattern: \"{}\".", name,
                       aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    const std::byte *found_address_start =
        find_pattern(reinterpret_cast<const std::byte *>(module_base), module_size, pattern.value());
    if (!found_address_start)
    {
        m_logger.error("HookManager: AOB pattern not found for inline hook '{}'. Pattern: \"{}\".", name,
                       aob_pattern_str);
        if (original_trampoline)
            *original_trampoline = nullptr;
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger.debug(
        "HookManager: AOB pattern for inline hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
        name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(found_address_start)),
        DetourModKit::Format::format_hex(aob_offset), DetourModKit::Format::format_address(target_address));

    return create_inline_hook(name, target_address, detour_function, original_trampoline, config);
}

std::expected<std::string, HookError> HookManager::create_mid_hook(std::string_view name, uintptr_t target_address,
                                                                   safetyhook::MidHookFn detour_function,
                                                                   const HookConfig &config)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.error("HookManager: Shutdown in progress. Cannot create mid hook '{}'.", name);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant create_mid_hook('{}') from within a with_*/try_with_* callback "
                       "rejected; defer hook mutation until the callback returns.",
                       name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result,
          deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);

        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot create mid hook '{}'.", name),
                      LogLevel::Error}}};
        }
        if (!m_allocator)
        {
            return {std::unexpected(HookError::AllocatorNotAvailable),
                    {{std::format("HookManager: Allocator not available. Cannot create mid hook '{}'.", name),
                      LogLevel::Error}}};
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

        // Mid hooks are implemented as SafetyHook inline hooks at the requested address, so they participate in the
        // same address-layering rules as create_inline_hook().
        std::string layered_on_managed_hook;
        if (const std::string *self_owner = find_hook_owner_of_target_locked(target_address))
        {
            if (config.fail_if_already_hooked)
            {
                return {std::unexpected(HookError::TargetAlreadyHookedInProcess),
                        {{std::format("HookManager: Target {} for mid hook '{}' is already hooked by managed hook "
                                      "'{}'. Aborting under strict mode.",
                                      DetourModKit::Format::format_address(target_address), name, *self_owner),
                          LogLevel::Error}}};
            }
            layered_on_managed_hook = *self_owner;
        }

        PrehookDetection prehook;
        if (layered_on_managed_hook.empty())
        {
            prehook = detect_existing_inline_hook(target_address);
            if (prehook.state == PrehookState::HookedByOtherModule && config.fail_if_already_hooked)
            {
                return {
                    std::unexpected(HookError::TargetAlreadyHookedInProcess),
                    {{std::format("HookManager: Target {} for mid hook '{}' is already inline-hooked by another module "
                                  "(JMP -> {}). Aborting under strict mode.",
                                  DetourModKit::Format::format_address(target_address), name,
                                  DetourModKit::Format::format_address(prehook.jmp_destination)),
                      LogLevel::Error}}};
            }
        }

        try
        {
            auto sh_flags = config.auto_enable ? safetyhook::MidHook::Default : safetyhook::MidHook::StartDisabled;

            auto hook_creation_result = safetyhook::MidHook::create(
                m_allocator, reinterpret_cast<void *>(target_address), detour_function, sh_flags);

            if (!hook_creation_result)
            {
                return {std::unexpected(HookError::SafetyHookError),
                        {{std::format("HookManager: Failed to create SafetyHook::MidHook for '{}' at {}. Error: {}",
                                      name, DetourModKit::Format::format_address(target_address),
                                      error_to_string(hook_creation_result.error())),
                          LogLevel::Error}}};
            }

            auto sh_mid_hook = std::move(hook_creation_result.value());

            HookStatus initial_status = sh_mid_hook.enabled() ? HookStatus::Active : HookStatus::Disabled;

            // Pre-build log entries before committing to m_hooks so that allocation failures in std::format cannot
            // leave a ghost hook.
            std::string status_message = (initial_status == HookStatus::Active) ? "and enabled" : "(disabled)";
            std::vector<DeferredLogEntry> logs;
            logs.reserve(3);
            logs.push_back({std::format("HookManager: Successfully created {} mid hook '{}' targeting {}.",
                                        status_message, name, DetourModKit::Format::format_address(target_address)),
                            LogLevel::Info});

            if (!layered_on_managed_hook.empty())
            {
                logs.push_back(
                    {std::format("HookManager: Target {} for mid hook '{}' is already hooked by managed hook '{}'; "
                                 "SafetyHook layered on top. Remove layered hooks newest-first.",
                                 DetourModKit::Format::format_address(target_address), name, layered_on_managed_hook),
                     LogLevel::Warning});
            }
            else if (prehook.state == PrehookState::HookedByOtherModule)
            {
                logs.push_back(
                    {std::format("HookManager: Target {} for mid hook '{}' was already inline-hooked by another "
                                 "module (JMP -> {}); SafetyHook layered on top.",
                                 DetourModKit::Format::format_address(target_address), name,
                                 DetourModKit::Format::format_address(prehook.jmp_destination)),
                     LogLevel::Warning});
            }

            if (initial_status == HookStatus::Disabled && config.auto_enable)
            {
                logs.push_back({std::format("HookManager: Mid hook '{}' was configured for auto-enable "
                                            "but is currently disabled post-creation.",
                                            name),
                                LogLevel::Warning});
            }

            std::string name_str{name};
            auto managed_hook =
                std::make_unique<MidHook>(name_str, target_address, std::move(sh_mid_hook), initial_status);
            // Record creation order before emplace so layered hooks unwind newest-first at teardown; a stale entry from
            // a throwing emplace is a harmless skip there. Mid hooks share m_hooks and the same prologue-overlap
            // hazard as inline hooks, so they participate in the same ordered teardown.
            m_hook_creation_order.push_back(name_str);
            m_hooks.emplace(name_str, std::move(managed_hook));

            return {std::move(name_str), std::move(logs)};
        }
        catch (const std::exception &e)
        {
            return {std::unexpected(HookError::UnknownError),
                    {{std::format("HookManager: An std::exception occurred during mid hook creation for '{}': {}", name,
                                  e.what()),
                      LogLevel::Error}}};
        }
        catch (...)
        {
            return {
                std::unexpected(HookError::UnknownError),
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

std::expected<std::string, HookError>
HookManager::create_mid_hook_aob(std::string_view name, uintptr_t module_base, size_t module_size,
                                 std::string_view aob_pattern_str, ptrdiff_t aob_offset,
                                 safetyhook::MidHookFn detour_function, const HookConfig &config)
{
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant create_mid_hook_aob('{}') from within a with_*/try_with_* callback "
                       "rejected; defer hook mutation until the callback returns.",
                       name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    m_logger.debug("HookManager: Attempting AOB scan for mid hook '{}' with pattern: \"{}\", offset: {}.", name,
                   aob_pattern_str, DetourModKit::Format::format_hex(aob_offset));

    auto pattern = parse_aob(aob_pattern_str);
    if (!pattern.has_value())
    {
        m_logger.error("HookManager: AOB pattern parsing failed for mid hook '{}'. Pattern: \"{}\".", name,
                       aob_pattern_str);
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    const std::byte *found_address_start =
        find_pattern(reinterpret_cast<const std::byte *>(module_base), module_size, pattern.value());
    if (!found_address_start)
    {
        m_logger.error("HookManager: AOB pattern not found for mid hook '{}'. Pattern: \"{}\".", name, aob_pattern_str);
        return std::unexpected(HookError::InvalidTargetAddress);
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(found_address_start) + aob_offset;
    m_logger.debug(
        "HookManager: AOB pattern for mid hook '{}' found at {}. Applying offset {}. Final target hook address: {}.",
        name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(found_address_start)),
        DetourModKit::Format::format_hex(aob_offset), DetourModKit::Format::format_address(target_address));

    return create_mid_hook(name, target_address, detour_function, config);
}

bool HookManager::is_target_already_hooked(uintptr_t target_address) const noexcept
{
    if (target_address == 0)
    {
        return false;
    }
    const auto lock = lock_hooks_shared_reentrant();
    return find_hook_owner_of_target_locked(target_address) != nullptr;
}

const std::string *HookManager::find_vmt_owner_of_vptr_locked(std::uintptr_t vptr) const noexcept
{
    if (vptr == 0)
    {
        return nullptr;
    }
    for (const auto &[name, entry] : m_vmt_hooks)
    {
        if (entry.cloned_vptr_base() != 0 && entry.cloned_vptr_base() == vptr)
        {
            return &name;
        }
    }
    return nullptr;
}

const std::string *HookManager::find_hook_owner_of_target_locked(uintptr_t target_address) const noexcept
{
    if (target_address == 0)
    {
        return nullptr;
    }
    // Match on the patched address irrespective of hook type: an inline hook and a mid hook (or two of either) at the
    // same address overlap the same prologue bytes, so both share the layered-teardown hazard.
    for (const auto &[name, hook_ptr] : m_hooks)
    {
        if (hook_ptr->get_target_address() == target_address)
        {
            return &name;
        }
    }
    return nullptr;
}

void HookManager::clear_vmt_hooks_locked() noexcept
{
    // Newest-first so layered clones unwind with every conditional vptr restore targeting live memory.
    for (auto it = m_vmt_creation_order.rbegin(); it != m_vmt_creation_order.rend(); ++it)
    {
        m_vmt_hooks.erase(*it);
    }
    m_vmt_hooks.clear();
    m_vmt_creation_order.clear();
}

void HookManager::disable_hooks_reverse_order_locked() noexcept
{
    // Newest-first restore so a hook layered on a shared target rewrites the prologue to the jump into the older
    // hook before that older hook restores the true original bytes; see the member doc for the use-after-free this
    // ordering prevents. Names absent from m_hooks (a creation that failed after recording its order entry) are
    // skipped harmlessly.
    for (auto it = m_hook_creation_order.rbegin(); it != m_hook_creation_order.rend(); ++it)
    {
        auto hook_it = m_hooks.find(*it);
        if (hook_it != m_hooks.end())
        {
            (void)hook_it->second->disable();
        }
    }
}

void HookManager::clear_hooks_locked() noexcept
{
    // Newest-first for symmetry with the disable phase; every hook is already disabled here, so this only frees
    // trampolines.
    for (auto it = m_hook_creation_order.rbegin(); it != m_hook_creation_order.rend(); ++it)
    {
        m_hooks.erase(*it);
    }
    m_hooks.clear();
    m_hook_creation_order.clear();
}

bool HookManager::looks_like_function_vmt_slot(std::uintptr_t slot_value) noexcept
{
    // A zero vtable slot is the RTTI/garbage sentinel SafetyHook itself rejects in VmtHook::create when probing for the
    // vtable end. Treat it as a non-function.
    if (slot_value == 0)
    {
        return false;
    }

    // Reject 0xCC/0xCD padding or breakpoints and bare RETs. A 0x00 first byte is the uninitialised-page sentinel.
    std::uint8_t first_byte = 0;
    if (!Memory::seh_read_bytes(slot_value, &first_byte, sizeof(first_byte)))
    {
        // Unreadable: cannot prove it is a function, refuse.
        return false;
    }
    switch (first_byte)
    {
    case 0x00:
    case 0xCC:
    case 0xCD:
    case 0xC2:
    case 0xC3:
        return false;
    default:
        break;
    }

    // Same-module jump-stub check. MSVC x64 adjustor thunks begin with the this-adjust instruction (first byte 0x48),
    // so they pass this check; a slot whose *first* byte is EB (jmp rel8) or E9 (jmp rel32) landing in the same module
    // is a jump stub (an incremental-link ILT entry or a patched slot), not a function body. Cloning a stub makes the
    // new "original" a forwarder rather than the real body. "Same module" means HMODULE identity per
    // GetModuleHandleExW on the slot and jump-target addresses, not a distance heuristic. Tail-calls that land in a
    // foreign module (a `mov reg,reg; jmp <foreign>`) are real functions and pass.
    if (first_byte == 0xEB || first_byte == 0xE9)
    {
        HMODULE slot_module = nullptr;
        HMODULE jmp_module = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(slot_value), &slot_module) == 0)
        {
            // No module info: cannot prove same-module, let the caller decide. Reject conservatively.
            return false;
        }
        // Resolve the jmp target through the same x86 decode primitives the inline-hook pre-flight uses; that way
        // EB and E9 share one well-tested decoder path.
        std::optional<std::uintptr_t> jmp_target;
        if (first_byte == 0xE9)
        {
            jmp_target = detail::decode_e9_rel32(slot_value);
        }
        else
        {
            jmp_target = detail::decode_eb_rel8(slot_value);
        }
        if (!jmp_target)
        {
            return false;
        }
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(*jmp_target), &jmp_module) == 0)
        {
            return false;
        }
        if (slot_module == jmp_module)
        {
            return false;
        }
    }

    return true;
}

std::expected<void, HookError> HookManager::remove_hook(std::string_view hook_id)
{
    // Non-locking fast-fail before acquiring the mutator gate.
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot remove hook '{}'.", hook_id);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant remove_hook('{}') from within a with_*/try_with_* callback rejected; "
                         "defer hook mutation until the callback returns.",
                         hook_id);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<void, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);

        // Re-check after acquiring the gate. A thread can observe shutdown as false above, then block here behind
        // remove_all_hooks()'s exclusive gate; once that releases (with m_shutdown_called reset to false) this would
        // otherwise proceed against freshly reset reusable state. The post-gate re-check makes remove uniform with
        // create/enable/disable.
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot remove hook '{}'.", hook_id),
                      LogLevel::Warning}}};
        }

        // Two-phase removal: disable under the shared lock first, then take the exclusive lock to erase. The shared
        // phase lets the kit's own with_inline_hook readers (shared_lock holders) finish before the Hook is destroyed;
        // SafetyHook's disable()/destructor relocates only threads caught in the patched prologue, not threads already
        // in the detour or trampoline body. Sequencing disable() before the exclusive clear also keeps SafetyHook's own
        // thread-suspend teardown off the exclusive lock. The caller must ensure no thread is executing the hooked
        // function during removal to close the residual narrow window.
        {
            std::shared_lock<detail::SrwSharedMutex> shared(m_hooks_mutex);
            auto it = m_hooks.find(hook_id);
            if (it == m_hooks.end())
            {
                return {
                    std::unexpected(HookError::HookNotFound),
                    {{std::format("HookManager: Attempted to remove hook with ID '{}', but it was not found.", hook_id),
                      LogLevel::Warning}}};
            }
            (void)it->second->disable();
        }

        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        std::vector<DeferredLogEntry> logs;
        auto it = m_hooks.find(hook_id);
        if (it == m_hooks.end())
        {
            // The hook existed under the shared phase above but a concurrent removal erased it before this exclusive
            // erase phase. Report not-found rather than a false success.
            return {std::unexpected(HookError::HookNotFound),
                    {{std::format("HookManager: Hook '{}' was concurrently removed before this removal completed.",
                                  hook_id),
                      LogLevel::Warning}}};
        }
        std::string name_of_removed_hook = it->second->get_name();
        HookType type_of_removed_hook = it->second->get_type();
        m_hooks.erase(it);
        std::erase(m_hook_creation_order, name_of_removed_hook);
        logs.push_back(
            {std::format("HookManager: Hook '{}' of type '{}' has been removed and unhooked.", name_of_removed_hook,
                         (type_of_removed_hook == HookType::Inline ? "Inline" : "Mid")),
             LogLevel::Debug});
        return {std::expected<void, HookError>{}, std::move(logs)};
    }();

    // Emit collected messages after all hook locks are released (deferred logging keeps the Logger's own locks off this
    // module's critical sections).
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

void HookManager::remove_all_hooks()
{
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant remove_all_hooks() from within a with_*/try_with_* callback rejected; "
                         "defer hook teardown until the callback returns.");
        return;
    }

    // Serialize with shutdown() via compare_exchange_strong. Only one teardown owner proceeds.
    bool expected = false;
    if (!m_shutdown_called.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;

    size_t num_vmt = 0;
    size_t num_hooks = 0;
    {
        // Block all mutators (create_*_hook, enable, disable, remove) before entering phase 1. They hold shared on
        // m_mutator_gate, so acquiring exclusive here waits for active mutators and blocks new ones.
        std::unique_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);

        // Two-phase removal: disable hooks under the shared lock first, then take the exclusive lock to erase. The
        // shared phase lets the kit's own with_inline_hook readers (shared_lock holders) finish before the Hook is
        // destroyed; SafetyHook relocates only threads caught in the patched prologue, not threads already in the
        // detour or trampoline body, so the caller must quiesce the hooked function during teardown to close the
        // residual narrow window.
        {
            std::shared_lock<detail::SrwSharedMutex> shared(m_hooks_mutex);
            disable_hooks_reverse_order_locked();
        }

        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);

        num_vmt = m_vmt_hooks.size();
        clear_vmt_hooks_locked();

        num_hooks = m_hooks.size();
        clear_hooks_locked();

        // Reset under the lock so concurrent create_*_hook calls cannot observe the flag as true (rejected) and then
        // immediately see it as false (accepted) before the maps are fully cleared. Both locks are released when this
        // block exits, letting new mutators proceed against a fresh m_shutdown_called == false.
        m_shutdown_called.store(false, std::memory_order_release);
    }

    // Emit the teardown logs only after the hooks mutex and the mutator gate are both released, so the logger's sink
    // I/O never extends either critical section (deferred-logging convention, matching the create_*_hook paths).
    if (num_vmt > 0)
    {
        m_logger.debug("HookManager: Removed all {} VMT hooks.", num_vmt);
    }
    if (num_hooks > 0)
    {
        m_logger.debug("HookManager: Removed all {} managed hooks and unhooked them.", num_hooks);
    }
    else if (num_vmt == 0)
    {
        m_logger.debug("HookManager: remove_all_hooks called, but no hooks were active to remove.");
    }
}

std::expected<void, HookError> HookManager::enable_hook(std::string_view hook_id)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot enable hook '{}'.", hook_id);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant enable_hook('{}') from within a with_*/try_with_* callback rejected; "
                         "defer hook mutation until the callback returns.",
                         hook_id);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<void, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot enable hook '{}'.", hook_id),
                      LogLevel::Warning}}};
        }
        auto it = m_hooks.find(hook_id);
        if (it == m_hooks.end())
        {
            return {std::unexpected(HookError::HookNotFound),
                    {{std::format("HookManager: Hook ID '{}' not found for enable operation.", hook_id),
                      LogLevel::Warning}}};
        }

        Hook *hook = it->second.get();
        auto enable_result = hook->enable();
        if (enable_result)
        {
            return {std::expected<void, HookError>{},
                    {{std::format("HookManager: Hook '{}' successfully enabled.", hook_id), LogLevel::Debug}}};
        }

        const auto error = enable_result.error();
        if (error == HookError::InvalidHookState)
        {
            return {std::unexpected(error),
                    {{std::format("HookManager: Hook '{}' cannot be enabled. Current status: {}", hook_id,
                                  Hook::status_to_string(hook->get_status())),
                      LogLevel::Warning}}};
        }
        return {std::unexpected(error),
                {{std::format("HookManager: Failed to enable hook '{}': {}", hook_id, Hook::error_to_string(error)),
                  LogLevel::Error}}};
    }();

    // Emit after releasing the gate and hook lock (deferred logging).
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

std::expected<void, HookError> HookManager::disable_hook(std::string_view hook_id)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot disable hook '{}'.", hook_id);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant disable_hook('{}') from within a with_*/try_with_* callback rejected; "
                         "defer hook mutation until the callback returns.",
                         hook_id);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<void, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot disable hook '{}'.", hook_id),
                      LogLevel::Warning}}};
        }
        auto it = m_hooks.find(hook_id);
        if (it == m_hooks.end())
        {
            return {std::unexpected(HookError::HookNotFound),
                    {{std::format("HookManager: Hook ID '{}' not found for disable operation.", hook_id),
                      LogLevel::Warning}}};
        }

        Hook *hook = it->second.get();
        auto disable_result = hook->disable();
        if (disable_result)
        {
            return {std::expected<void, HookError>{},
                    {{std::format("HookManager: Hook '{}' successfully disabled.", hook_id), LogLevel::Debug}}};
        }

        const auto error = disable_result.error();
        if (error == HookError::InvalidHookState)
        {
            return {std::unexpected(error),
                    {{std::format("HookManager: Hook '{}' cannot be disabled. Current status: {}", hook_id,
                                  Hook::status_to_string(hook->get_status())),
                      LogLevel::Warning}}};
        }
        return {std::unexpected(error),
                {{std::format("HookManager: Failed to disable hook '{}': {}", hook_id, Hook::error_to_string(error)),
                  LogLevel::Error}}};
    }();

    // Emit after releasing the gate and hook lock (deferred logging).
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

bool HookManager::toggle_hook_locked(std::string_view hook_id, Hook &hook, bool enable,
                                     std::vector<DeferredLogEntry> &logs)
{
    auto result = enable ? hook.enable() : hook.disable();
    // "enable" + 'd' / "disable" + 'd' reads as "enabled" / "disabled" in the log.
    const std::string_view verb = enable ? "enable" : "disable";
    if (result)
    {
        logs.push_back({std::format("HookManager: Hook '{}' successfully {}d.", hook_id, verb), LogLevel::Debug});
        return true;
    }

    const auto error = result.error();
    if (error == HookError::InvalidHookState)
    {
        logs.push_back({std::format("HookManager: Hook '{}' cannot be {}d. Current status: {}", hook_id, verb,
                                    Hook::status_to_string(hook.get_status())),
                        LogLevel::Warning});
    }
    else
    {
        logs.push_back(
            {std::format("HookManager: Failed to {} hook '{}': {}", verb, hook_id, Hook::error_to_string(error)),
             LogLevel::Error});
    }
    return false;
}

std::size_t HookManager::enable_hooks(std::span<const std::string_view> hook_ids)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot enable {} hook(s).", hook_ids.size());
        return 0;
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant enable_hooks() from within a with_*/try_with_* callback rejected; defer "
                       "hook mutation until the callback returns.");
        return 0;
    }

    auto [enabled, deferred_logs] = [&]() -> std::pair<std::size_t, std::vector<DeferredLogEntry>>
    {
        std::vector<DeferredLogEntry> logs;
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            logs.push_back(
                {std::format("HookManager: Shutdown in progress. Cannot enable {} hook(s).", hook_ids.size()),
                 LogLevel::Warning});
            return {0, std::move(logs)};
        }

        std::size_t count = 0;
        for (const std::string_view hook_id : hook_ids)
        {
            auto it = m_hooks.find(hook_id);
            if (it == m_hooks.end())
            {
                logs.push_back({std::format("HookManager: Hook ID '{}' not found for enable operation.", hook_id),
                                LogLevel::Warning});
                continue;
            }
            if (toggle_hook_locked(hook_id, *it->second, true, logs))
            {
                ++count;
            }
        }
        return {count, std::move(logs)};
    }();

    // Emit after releasing the gate and hook lock (deferred logging) so a synchronous sink flush or a blocking async
    // overflow never stalls an exclusive acquirer inside the critical section.
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return enabled;
}

std::size_t HookManager::disable_hooks(std::span<const std::string_view> hook_ids)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot disable {} hook(s).", hook_ids.size());
        return 0;
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant disable_hooks() from within a with_*/try_with_* callback rejected; "
                       "defer hook mutation until the callback returns.");
        return 0;
    }

    auto [disabled, deferred_logs] = [&]() -> std::pair<std::size_t, std::vector<DeferredLogEntry>>
    {
        std::vector<DeferredLogEntry> logs;
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            logs.push_back(
                {std::format("HookManager: Shutdown in progress. Cannot disable {} hook(s).", hook_ids.size()),
                 LogLevel::Warning});
            return {0, std::move(logs)};
        }

        std::size_t count = 0;
        for (const std::string_view hook_id : hook_ids)
        {
            auto it = m_hooks.find(hook_id);
            if (it == m_hooks.end())
            {
                logs.push_back({std::format("HookManager: Hook ID '{}' not found for disable operation.", hook_id),
                                LogLevel::Warning});
                continue;
            }
            if (toggle_hook_locked(hook_id, *it->second, false, logs))
            {
                ++count;
            }
        }
        return {count, std::move(logs)};
    }();

    // Emit after releasing the gate and hook lock (deferred logging) so a synchronous sink flush or a blocking async
    // overflow never stalls an exclusive acquirer inside the critical section.
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return disabled;
}

std::size_t HookManager::enable_all_hooks()
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot enable all hooks.");
        return 0;
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant enable_all_hooks() from within a with_*/try_with_* callback rejected; "
                       "defer hook mutation until the callback returns.");
        return 0;
    }

    auto [enabled, deferred_logs] = [&]() -> std::pair<std::size_t, std::vector<DeferredLogEntry>>
    {
        std::vector<DeferredLogEntry> logs;
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            logs.push_back({"HookManager: Shutdown in progress. Cannot enable all hooks.", LogLevel::Warning});
            return {0, std::move(logs)};
        }

        std::size_t count = 0;
        for (const auto &[hook_id, hook] : m_hooks)
        {
            if (toggle_hook_locked(hook_id, *hook, true, logs))
            {
                ++count;
            }
        }
        return {count, std::move(logs)};
    }();

    // Emit after releasing the gate and hook lock (deferred logging) so a synchronous sink flush or a blocking async
    // overflow never stalls an exclusive acquirer inside the critical section.
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return enabled;
}

std::size_t HookManager::disable_all_hooks()
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot disable all hooks.");
        return 0;
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant disable_all_hooks() from within a with_*/try_with_* callback rejected; "
                       "defer hook mutation until the callback returns.");
        return 0;
    }

    auto [disabled, deferred_logs] = [&]() -> std::pair<std::size_t, std::vector<DeferredLogEntry>>
    {
        std::vector<DeferredLogEntry> logs;
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::shared_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            logs.push_back({"HookManager: Shutdown in progress. Cannot disable all hooks.", LogLevel::Warning});
            return {0, std::move(logs)};
        }

        std::size_t count = 0;
        for (const auto &[hook_id, hook] : m_hooks)
        {
            if (toggle_hook_locked(hook_id, *hook, false, logs))
            {
                ++count;
            }
        }
        return {count, std::move(logs)};
    }();

    // Emit after releasing the gate and hook lock (deferred logging) so a synchronous sink flush or a blocking async
    // overflow never stalls an exclusive acquirer inside the critical section.
    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return disabled;
}

std::optional<HookStatus> HookManager::get_hook_status(std::string_view hook_id) const
{
    const auto lock = lock_hooks_shared_reentrant();
    auto it = m_hooks.find(hook_id);
    if (it != m_hooks.end())
    {
        return it->second->get_status();
    }
    return std::nullopt;
}

std::unordered_map<HookStatus, size_t> HookManager::get_hook_counts() const
{
    const auto lock = lock_hooks_shared_reentrant();
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
    const auto lock = lock_hooks_shared_reentrant();
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

std::expected<std::string, HookError> HookManager::create_vmt_hook(std::string_view name, void *object)
{
    return create_vmt_hook(name, object, VmtHookConfig{});
}

std::expected<std::string, HookError> HookManager::create_vmt_hook(std::string_view name, void *object,
                                                                   const VmtHookConfig &cfg)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.error("HookManager: Shutdown in progress. Cannot create VMT hook '{}'.", name);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.error("HookManager: Reentrant create_vmt_hook('{}') from within a with_*/try_with_* callback "
                       "rejected; defer hook mutation until the callback returns.",
                       name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result,
          deferred_logs] = [&]() -> std::pair<std::expected<std::string, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);

        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot create VMT hook '{}'.", name),
                      LogLevel::Error}}};
        }
        if (object == nullptr)
        {
            return {std::unexpected(HookError::InvalidObject),
                    {{std::format("HookManager: Object pointer is NULL for VMT hook '{}'.", name), LogLevel::Error}}};
        }
        if (vmt_hook_exists_locked(name))
        {
            return {
                std::unexpected(HookError::HookAlreadyExists),
                {{std::format("HookManager: A VMT hook with the name '{}' already exists.", name), LogLevel::Error}}};
        }

        // Pre-flight: read the current vptr and reject if it points at a vtable already cloned by this HookManager.
        // SafetyHook::VmtHook::create silently overwrites the vptr with a pointer into a fresh clone, and a second
        // call later sees the first clone as the "original" and chains on top of it. The guard makes the failure
        // mode visible to the consumer. The reads are SEH-guarded: a garbage vptr is exactly what the opt-in flags
        // exist to reject, so an unreadable object or vtable fails closed instead of faulting. When both flags are
        // false no read is performed and the legacy path is unchanged.
        if (cfg.fail_if_already_hooked || cfg.fail_on_non_function_pointer)
        {
            const auto current_vptr = Memory::seh_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
            if (!current_vptr)
            {
                return {std::unexpected(HookError::InvalidObject),
                        {{std::format("HookManager: VMT hook '{}' refused: object {} vptr is unreadable.", name,
                                      DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                          LogLevel::Error}}};
            }
            if (cfg.fail_if_already_hooked)
            {
                if (const auto *owner = find_vmt_owner_of_vptr_locked(*current_vptr))
                {
                    return {
                        std::unexpected(HookError::HookAlreadyExists),
                        {{std::format(
                              "HookManager: VMT hook '{}' refused: object {} is already on the clone owned by '{}'.",
                              name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)), *owner),
                          LogLevel::Error}}};
                }
            }

            // Pre-flight: refuse to clone when the first slot does not look like a callable function body. A 0xCC
            // byte is an int3 alignment pad or permanent breakpoint; an EB/E9 same-module slot is a jump stub and
            // cloning it makes the new "original" a forwarder. Tail-calls to outside the module (a `mov reg,reg; jmp`
            // to a foreign function) are real functions and pass through.
            if (cfg.fail_on_non_function_pointer)
            {
                const auto slot0 = Memory::seh_read<std::uintptr_t>(*current_vptr);
                if (!slot0)
                {
                    return {std::unexpected(HookError::InvalidObject),
                            {{std::format("HookManager: VMT hook '{}' refused: object {} vtable is unreadable.", name,
                                          DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                              LogLevel::Error}}};
                }
                if (!looks_like_function_vmt_slot(*slot0))
                {
                    return {
                        std::unexpected(HookError::InvalidObject),
                        {{std::format("HookManager: VMT hook '{}' refused: object {} first slot {} is not a "
                                      "function pointer.",
                                      name, DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)),
                                      DetourModKit::Format::format_address(*slot0)),
                          LogLevel::Error}}};
                }
            }
        }

        try
        {
            auto vmt_result = safetyhook::VmtHook::create(object);

            if (!vmt_result)
            {
                return {std::unexpected(HookError::SafetyHookError),
                        {{std::format("HookManager: Failed to create SafetyHook::VmtHook for '{}' on object {}.", name,
                                      DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                          LogLevel::Error}}};
            }

            // Capture the vptr SafetyHook just installed. After create, *object == &hook.m_new_vmt[1], which is the
            // value any future apply_vmt_hook call will see on this object. Recording it lets later
            // fail_if_already_hooked checks recognize "object is on this clone" without poking at SafetyHook's private
            // layout. The emplace-arg constructor takes the base as a third arg and stores it.
            const std::uintptr_t new_vptr_base = *reinterpret_cast<std::uintptr_t *>(object);

            std::string name_str{name};

            std::vector<DeferredLogEntry> logs;
            logs.push_back({std::format("HookManager: Successfully created VMT hook '{}' on object {}.", name,
                                        DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                            LogLevel::Info});

            // Record creation order before emplace: if emplace throws, the stale order entry is a harmless no-op
            // erase at teardown, whereas a registered hook missing from the order vector would dodge the ordered
            // teardown.
            m_vmt_creation_order.push_back(name_str);
            m_vmt_hooks.emplace(std::piecewise_construct, std::forward_as_tuple(name_str),
                                std::forward_as_tuple(name_str, std::move(vmt_result.value()), new_vptr_base));

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

std::expected<void, HookError> HookManager::remove_vmt_hook(std::string_view vmt_name)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot remove VMT hook '{}'.", vmt_name);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant remove_vmt_hook('{}') from within a with_*/try_with_* callback "
                         "rejected; defer hook mutation until the callback returns.",
                         vmt_name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<void, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        // Re-check after acquiring the gate so a teardown that flipped m_shutdown_called while we waited is not raced
        // (uniform with the create/enable/disable mutators).
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot remove VMT hook '{}'.", vmt_name),
                      LogLevel::Warning}}};
        }
        auto it = m_vmt_hooks.find(vmt_name);
        if (it != m_vmt_hooks.end())
        {
            std::string removed_name = it->second.get_name();
            m_vmt_hooks.erase(it);
            std::erase(m_vmt_creation_order, removed_name);
            return {std::expected<void, HookError>{},
                    {{std::format("HookManager: VMT hook '{}' has been removed.", removed_name), LogLevel::Debug}}};
        }
        return {std::unexpected(HookError::VmtHookNotFound),
                {{std::format("HookManager: Attempted to remove VMT hook '{}', but it was not found.", vmt_name),
                  LogLevel::Warning}}};
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

std::expected<void, HookError> HookManager::remove_vmt_method(std::string_view vmt_name, size_t method_index)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot remove VMT method on '{}'.", vmt_name);
        return std::unexpected(HookError::ShutdownInProgress);
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant remove_vmt_method('{}') from within a with_*/try_with_* callback "
                         "rejected; defer hook mutation until the callback returns.",
                         vmt_name);
        return std::unexpected(HookError::ReentrantCallRejected);
    }

    auto [result, deferred_logs] = [&]() -> std::pair<std::expected<void, HookError>, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {std::unexpected(HookError::ShutdownInProgress),
                    {{std::format("HookManager: Shutdown in progress. Cannot remove VMT method on '{}'.", vmt_name),
                      LogLevel::Warning}}};
        }
        auto it = m_vmt_hooks.find(vmt_name);
        if (it == m_vmt_hooks.end())
        {
            return {std::unexpected(HookError::VmtHookNotFound),
                    {{std::format("HookManager: VMT hook '{}' not found for method removal.", vmt_name),
                      LogLevel::Warning}}};
        }

        if (it->second.remove_method_hook(method_index))
        {
            return {std::expected<void, HookError>{},
                    {{std::format("HookManager: VMT '{}' method index {} has been unhooked.", vmt_name, method_index),
                      LogLevel::Debug}}};
        }
        return {std::unexpected(HookError::MethodNotFound),
                {{std::format("HookManager: VMT '{}' has no hooked method at index {}.", vmt_name, method_index),
                  LogLevel::Warning}}};
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

bool HookManager::apply_vmt_hook(std::string_view vmt_name, void *object)
{
    return apply_vmt_hook(vmt_name, object, VmtHookConfig{});
}

bool HookManager::apply_vmt_hook(std::string_view vmt_name, void *object, const VmtHookConfig &cfg)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot apply VMT hook '{}'.", vmt_name);
        return false;
    }
    if (object == nullptr)
    {
        m_logger.warning("HookManager: Cannot apply VMT hook '{}' to null object.", vmt_name);
        return false;
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant apply_vmt_hook('{}') from within a with_*/try_with_* callback "
                         "rejected; defer hook mutation until the callback returns.",
                         vmt_name);
        return false;
    }

    auto [result, deferred_logs] = [&]() -> std::pair<bool, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {false,
                    {{std::format("HookManager: Shutdown in progress. Cannot apply VMT hook '{}'.", vmt_name),
                      LogLevel::Warning}}};
        }
        auto it = m_vmt_hooks.find(vmt_name);
        if (it == m_vmt_hooks.end())
        {
            return {false,
                    {{std::format("HookManager: VMT hook '{}' not found for apply.", vmt_name), LogLevel::Warning}}};
        }

        // The pre-flight reads are SEH-guarded: a garbage vptr is exactly what the opt-in flags exist to reject, so
        // an unreadable object or vtable fails closed instead of faulting. When both flags are false no read is
        // performed and the legacy path is unchanged.
        if (cfg.fail_if_already_hooked || cfg.fail_on_non_function_pointer)
        {
            const auto current_vptr = Memory::seh_read<std::uintptr_t>(reinterpret_cast<std::uintptr_t>(object));
            if (!current_vptr)
            {
                return {
                    false,
                    {{std::format("HookManager: VMT hook '{}' apply refused: object {} vptr is unreadable.", vmt_name,
                                  DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                      LogLevel::Error}}};
            }

            // Re-apply guard. SafetyHook::VmtHook::apply does m_objects.emplace(object, ...) which is silently
            // idempotent for a key that already exists; the guard makes the "already on this clone" case observable
            // for callers that want apply to be a clean no-op rather than a silent no-op. The lookup is registry-wide:
            // an object already on a clone owned by a *different* hook of this manager must be refused, not layered
            // onto. Mirrors create_vmt_hook's fail_if_already_hooked semantics.
            if (cfg.fail_if_already_hooked)
            {
                if (const auto *owner = find_vmt_owner_of_vptr_locked(*current_vptr))
                {
                    if (*owner == vmt_name)
                    {
                        return {
                            true,
                            {{std::format("HookManager: VMT hook '{}' already applied to object {}; no-op.", vmt_name,
                                          DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                              LogLevel::Debug}}};
                    }
                    return {false,
                            {{std::format("HookManager: VMT hook '{}' apply refused: object {} is already on the "
                                          "clone owned by '{}'.",
                                          vmt_name,
                                          DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)),
                                          *owner),
                              LogLevel::Error}}};
                }
            }

            // Re-run the pre-flight decoder against the vtable currently installed on the object (the one about to
            // be replaced). apply does not change the *target* vtable shape (only the vptr swap), so the decode is
            // identical to the create path: reject int3 padding, bare RETs, and same-module jump stubs at the
            // destination.
            if (cfg.fail_on_non_function_pointer)
            {
                const auto slot0 = Memory::seh_read<std::uintptr_t>(*current_vptr);
                if (!slot0)
                {
                    return {false,
                            {{std::format("HookManager: VMT hook '{}' apply refused: object {} vtable is unreadable.",
                                          vmt_name,
                                          DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                              LogLevel::Error}}};
                }
                if (!looks_like_function_vmt_slot(*slot0))
                {
                    return {false,
                            {{std::format("HookManager: VMT hook '{}' apply refused: object {} first slot {} is not "
                                          "a function pointer.",
                                          vmt_name,
                                          DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)),
                                          DetourModKit::Format::format_address(*slot0)),
                              LogLevel::Error}}};
                }
            }
        }

        // VmtHook::apply tracks the object in an internal container, so it can throw bad_alloc. Contain it here as
        // every other SafetyHook call site does, so a failed apply returns false instead of unwinding out through the
        // held locks.
        try
        {
            it->second.vmt_hook().apply(object);
        }
        catch (const std::exception &e)
        {
            return {false,
                    {{std::format("HookManager: Exception applying VMT hook '{}' to object {}: {}", vmt_name,
                                  DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object)), e.what()),
                      LogLevel::Error}}};
        }
        catch (...)
        {
            return {false,
                    {{std::format("HookManager: Unknown exception applying VMT hook '{}' to object {}.", vmt_name,
                                  DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                      LogLevel::Error}}};
        }
        return {true,
                {{std::format("HookManager: VMT hook '{}' applied to object {}.", vmt_name,
                              DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                  LogLevel::Debug}}};
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

bool HookManager::remove_vmt_from_object(std::string_view vmt_name, void *object)
{
    if (m_shutdown_called.load(std::memory_order_acquire))
    {
        m_logger.warning("HookManager: Shutdown in progress. Cannot remove VMT hook '{}' from object.", vmt_name);
        return false;
    }
    if (object == nullptr)
    {
        m_logger.warning("HookManager: Cannot remove VMT hook '{}' from null object.", vmt_name);
        return false;
    }
    // Fail closed on a reentrant call from inside a with_*/try_with_* callback: it holds m_hooks_mutex shared, so
    // re-acquiring this non-recursive lock here is UB / deadlock. Defer the mutation past the callback.
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning("HookManager: Reentrant remove_vmt_from_object('{}') from within a with_*/try_with_* callback "
                         "rejected; defer hook mutation until the callback returns.",
                         vmt_name);
        return false;
    }

    auto [result, deferred_logs] = [&]() -> std::pair<bool, std::vector<DeferredLogEntry>>
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return {
                false,
                {{std::format("HookManager: Shutdown in progress. Cannot remove VMT hook '{}' from object.", vmt_name),
                  LogLevel::Warning}}};
        }
        auto it = m_vmt_hooks.find(vmt_name);
        if (it == m_vmt_hooks.end())
        {
            return {false,
                    {{std::format("HookManager: VMT hook '{}' not found for object removal.", vmt_name),
                      LogLevel::Warning}}};
        }

        it->second.vmt_hook().remove(object);
        return {true,
                {{std::format("HookManager: VMT hook '{}' removed from object {}.", vmt_name,
                              DetourModKit::Format::format_address(reinterpret_cast<uintptr_t>(object))),
                  LogLevel::Debug}}};
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
    return result;
}

void HookManager::remove_all_vmt_hooks()
{
    if (get_reentrancy_guard() > 0)
    {
        m_logger.warning(
            "HookManager: Reentrant remove_all_vmt_hooks() from within a with_*/try_with_* callback rejected; defer "
            "hook teardown until the callback returns.");
        return;
    }

    if (m_shutdown_called.load(std::memory_order_acquire))
        return;

    std::vector<DeferredLogEntry> deferred_logs = [&]()
    {
        std::shared_lock<detail::SrwSharedMutex> mutator_gate(m_mutator_gate);
        std::unique_lock<detail::SrwSharedMutex> lock(m_hooks_mutex);
        std::vector<DeferredLogEntry> logs;
        if (m_shutdown_called.load(std::memory_order_acquire))
        {
            return logs;
        }
        if (!m_vmt_hooks.empty())
        {
            size_t num_hooks = m_vmt_hooks.size();
            clear_vmt_hooks_locked();
            logs.push_back(
                {std::format("HookManager: All {} VMT hooks have been removed.", num_hooks), LogLevel::Debug});
        }
        else
        {
            logs.push_back(
                {"HookManager: remove_all_vmt_hooks called, but no VMT hooks were active.", LogLevel::Debug});
        }
        return logs;
    }();

    for (const auto &entry : deferred_logs)
    {
        m_logger.log(entry.level, entry.msg);
    }
}

std::vector<std::string> HookManager::get_vmt_hook_names() const
{
    const auto lock = lock_hooks_shared_reentrant();
    std::vector<std::string> names;
    names.reserve(m_vmt_hooks.size());
    for (const auto &[name, entry] : m_vmt_hooks)
    {
        names.push_back(name);
    }
    return names;
}
