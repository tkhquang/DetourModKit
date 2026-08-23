/**
 * @file input_loader_detach_dll.cpp
 * @brief Hosts the T-INPUT-LOADER probe.
 */

#include "DetourModKit.hpp"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cwchar>
#include <iterator>
#include <memory>
#include <utility>

namespace
{
    std::atomic<bool> s_witness_armed{false};
    std::atomic<bool> s_staged{false};

    void make_capture_destroyed_event_name(wchar_t (&name)[96]) noexcept
    {
        (
            void
        )std::swprintf(name, std::size(name), L"Local\\DMK_InputLoader_CaptureDestroyed_%lu", GetCurrentProcessId());
    }

    /// Signals the host's witness event from its destructor once armed.
    class DestructionWitness
    {
    public:
        DestructionWitness() noexcept = default;
        DestructionWitness(const DestructionWitness &) noexcept = default;
        DestructionWitness(DestructionWitness &&) noexcept = default;
        DestructionWitness &operator=(const DestructionWitness &) noexcept = default;
        DestructionWitness &operator=(DestructionWitness &&) noexcept = default;
        ~DestructionWitness() noexcept
        {
            if (!s_witness_armed.load(std::memory_order_acquire))
            {
                return;
            }
            wchar_t event_name[96]{};
            make_capture_destroyed_event_name(event_name);
            if (const HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name))
            {
                (void)SetEvent(event);
                CloseHandle(event);
            }
        }
    };
} // namespace

/**
 * @brief Stages one press binding with a destruction witness and no engine.
 * @return TRUE after the binding enters staged storage and the function releases its guard owner.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_input_probe_stage() noexcept
{
    DetourModKit::Result<DetourModKit::input::BindingGuard> guard = DetourModKit::input::register_combo(
        DetourModKit::input::ComboBinding{
            .name = "loader_detach_staged",
            .trigger = DetourModKit::input::Trigger::Press,
            .combos = {{{DetourModKit::keyboard_key(0x70)}, {}}},
            .on_press = [witness = DestructionWitness{}] {},
        }
    );
    if (!guard.has_value())
    {
        return FALSE;
    }
    guard->release();
    s_staged.store(true, std::memory_order_release);
    return TRUE;
}

/**
 * @brief Parks one guard in the process-default Scope as the sole capture owner.
 * @return TRUE when staged entry removal leaves the parked guard as sole capture owner.
 * @details The probe checks capture lifetime before witness activation. Static destruction signals under the loader
 *          lock.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_input_probe_park_scope_guard() noexcept
{
    try
    {
        std::shared_ptr<char> capture_owner = std::make_shared<char>();
        const std::weak_ptr<char> capture_observer = capture_owner;
        DetourModKit::Result<DetourModKit::input::BindingGuard> guard = DetourModKit::input::register_combo(
            DetourModKit::input::ComboBinding{
                .name = "loader_detach_scope",
                .trigger = DetourModKit::input::Trigger::Press,
                .combos = {{{DetourModKit::keyboard_key(0x71)}, {}}},
                .on_press = [witness = DestructionWitness{}, keep_alive = std::move(capture_owner)] {},
            }
        );
        if (!guard.has_value())
        {
            return FALSE;
        }
        DetourModKit::input::scope().add(std::move(*guard));
        if (DetourModKit::input::Input::instance().remove_bindings_by_name("loader_detach_scope", false) != 1)
        {
            return FALSE;
        }
        if (capture_observer.expired())
        {
            return FALSE;
        }
        return TRUE;
    }
    catch (...)
    {
        return FALSE;
    }
}

/**
 * @brief Arms the witness after registration settled, so registration-time temporary copies never signal.
 */
extern "C" __declspec(dllexport) void WINAPI dmk_input_probe_arm_witness() noexcept
{
    s_witness_armed.store(true, std::memory_order_release);
}

/**
 * @brief Constructs and destroys one armed witness so the host proves the event can signal.
 * @return TRUE when the witness event was resolvable for the signal.
 */
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_input_probe_selftest_witness() noexcept
{
    wchar_t event_name[96]{};
    make_capture_destroyed_event_name(event_name);
    const HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, event_name);
    if (event == nullptr)
    {
        return FALSE;
    }
    CloseHandle(event);
    const bool was_armed = s_witness_armed.exchange(true, std::memory_order_acq_rel);
    {
        DestructionWitness control{};
    }
    s_witness_armed.store(was_armed, std::memory_order_release);
    return TRUE;
}

/// Reports whether the binding entered staged storage.
extern "C" __declspec(dllexport) INT_PTR WINAPI dmk_input_probe_staged() noexcept
{
    return s_staged.load(std::memory_order_acquire) ? TRUE : FALSE;
}

/**
 * @brief Takes the facade mutex on the current thread and leaves it locked.
 */
extern "C" __declspec(dllexport) void WINAPI dmk_input_probe_hold_facade_mutex() noexcept
{
    DetourModKit::input::Input::lock_facade_mutex_for_test();
}

/// Provides an address in this DLL's image for the host's mapped-state query.
extern "C" __declspec(dllexport) void dmk_input_probe_marker() noexcept {}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
