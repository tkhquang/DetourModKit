/**
 * @file mod_logic.cpp
 * @brief Reference logic DLL for the staged-generation reload pattern.
 */

#include <DetourModKit.hpp>

#include "protocol.h"

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>

namespace
{
    using namespace std::chrono_literals;

    using ApplyDamageFn = int (*)(int, int) noexcept;

    /// The build supplies DMK_EXAMPLE_MOD_NAME. One name derives the log, the INI, and every binding name.
    constexpr std::string_view MOD_NAME = DMK_EXAMPLE_MOD_NAME;

    /// Adds this bonus while the config toggle is on.
    constexpr int DAMAGE_BONUS = 25;

    constexpr auto HEARTBEAT_INTERVAL = 1s;
    constexpr auto HEARTBEAT_POLL = 100ms;

    /// Bounds the wait of one Shutdown for calls inside the detour. The loader retries a BUSY result.
    constexpr auto RETIREMENT_DEADLINE = 100ms;

    /// The oldest loader ABI that Init accepts. ABI 2 has the same request layout.
    constexpr std::uint32_t MIN_LOADER_ABI_VERSION = 2;

    std::optional<dmk::Session> s_session;
    dmk::hook::HookStack s_hooks;
    std::optional<dmk::StoppableWorker> s_heartbeat;
    std::atomic<ApplyDamageFn> s_original{nullptr};
    std::atomic<std::uint64_t> s_hook_calls{0};
    std::atomic<std::uint64_t> s_combo_presses{0};
    std::atomic<bool> s_bonus_enabled{true};
    dmk::staged_reload::Baseline s_baseline;
    // Zero until Init accepts a request, so a failed stage never returns a value that its loader does not know.
    std::uint32_t s_loader_abi_version = 0;
    bool s_worker_retirement_failed = false;

    /**
     * @brief Stands in for a game function that a real mod resolves with a scan ladder.
     * @details Volatile operands preserve a hookable body under optimization. A real mod resolves a game target.
     */
    __declspec(noinline) int demo_apply_damage(int amount, int resist) noexcept
    {
        volatile int observed_amount = amount;
        volatile int observed_resist = resist;
        return observed_amount - observed_resist;
    }

    int apply_damage_detour(int amount, int resist) noexcept
    {
        s_hook_calls.fetch_add(1, std::memory_order_relaxed);
        const ApplyDamageFn original = s_original.load(std::memory_order_acquire);
        if (original == nullptr)
        {
            return amount - resist;
        }
        const int bonus = s_bonus_enabled.load(std::memory_order_relaxed) ? DAMAGE_BONUS : 0;
        return original(amount + bonus, resist);
    }

    /**
     * @brief Stops the sample worker and latches any absent join proof.
     * @return true only when no worker module reference remains.
     */
    [[nodiscard]] bool stop_generation_workers() noexcept
    {
        s_heartbeat.reset();
        // A retained Worker reference can outlive its owner. The sample has no independent thread-exit proof.
        s_worker_retirement_failed = s_worker_retirement_failed ||
                                     dmk::diagnostics::module_pin_count(dmk::diagnostics::ModulePinReason::Worker) != 0;
        return !s_worker_retirement_failed;
    }

    /// Drops each reclaimable generation resource after a failed Init step.
    void roll_back_generation() noexcept
    {
        if (!stop_generation_workers())
        {
            return;
        }
        s_hooks.clear();
        s_session.reset();
    }
} // namespace

extern "C"
{
    /**
     * @brief Reports this build, so the loader can log which bytes it loaded (guide step 8).
     * @details The stamp moves only when this translation unit recompiles. A real mod exports its own build
     *          revision constant.
     */
    __declspec(dllexport) const char *DMK_WHEELHOST_CALL Revision() noexcept
    {
        return __DATE__ " " __TIME__;
    }

    /**
     * @brief Starts one generation with the loader's resident wheel host.
     * @param request The versioned request. Its host table remains valid for the process lifetime.
     * @return DMK_STAGED_RELOAD_OK when the generation is live, or zero when initialization fails.
     * @note The loader calls this from its control thread, off the loader lock.
     */
    __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL Init(const StagedReloadInitRequest *request) noexcept
    {
        // A HookManager leak means that a detour of this image stays reachable, so no generation starts beside it.
        if (request == nullptr || request->struct_size < sizeof(StagedReloadInitRequest) ||
            request->abi_version < MIN_LOADER_ABI_VERSION || request->abi_version > DMK_STAGED_RELOAD_ABI_VERSION ||
            request->generation_id == 0 || request->wheel_host == nullptr || request->expected_host_identity == 0 ||
            request->wheel_host->host_identity != request->expected_host_identity || s_session.has_value() ||
            s_worker_retirement_failed ||
            dmk::diagnostics::intentional_leak_count(dmk::diagnostics::LeakSubsystem::HookManager) != 0)
        {
            return 0;
        }
        s_baseline = dmk::staged_reload::capture();
        s_loader_abi_version = request->abi_version;
        try
        {
            auto started = dmk::Session::start(
                dmk::ModInfo{
                    .name = MOD_NAME,
                    .log_file = std::format("{}.log", MOD_NAME),
                    .log_open_mode = dmk::LogOpenMode::Append,
                }
            );
            if (!started)
            {
                return 0;
            }
            s_session.emplace(std::move(*started));

            dmk::config::bind_bool(
                "Damage",
                "EnableBonus",
                "Enable Damage Bonus",
                [](bool value) -> void { s_bonus_enabled.store(value, std::memory_order_relaxed); },
                true
            );

            auto installed = dmk::hook::inline_at<&apply_damage_detour>(dmk::hook::InlineRequest{
                .name = "demo_apply_damage",
                .target = dmk::Address{reinterpret_cast<std::uintptr_t>(&demo_apply_damage)},
            });
            if (!installed)
            {
                roll_back_generation();
                return 0;
            }
            dmk::hook::Hook &held = s_hooks.push(std::move(*installed));
            // Publish the original BEFORE enable(), so nothing can enter the detour unchained.
            s_original.store(held.original<ApplyDamageFn>(), std::memory_order_release);
            if (!held.enable())
            {
                roll_back_generation();
                return 0;
            }

            auto combo = dmk::config::press_combo(
                "Input",
                "DemoCombo",
                "Demo combo",
                std::format("{}.demo_combo", MOD_NAME),
                []() noexcept -> void { s_combo_presses.fetch_add(1, std::memory_order_relaxed); },
                "WheelUp",
                true
            );
            if (combo.name().empty())
            {
                roll_back_generation();
                return 0;
            }
            s_session->scope().add(std::move(combo));
            s_session->ini().load(std::format("{}.ini", MOD_NAME));

            // This worker calls the sample target. HookStack::retire drains its calls before Shutdown stops it.
            s_heartbeat.emplace(
                std::format("{}.heartbeat", MOD_NAME),
                [](const std::stop_token &token) -> void
                {
                    auto next_report = std::chrono::steady_clock::now() + HEARTBEAT_INTERVAL;
                    while (!token.stop_requested())
                    {
                        std::this_thread::sleep_for(HEARTBEAT_POLL);
                        if (std::chrono::steady_clock::now() < next_report)
                        {
                            continue;
                        }
                        next_report += HEARTBEAT_INTERVAL;
                        const int damage = demo_apply_damage(100, 10);
                        (void)dmk::log().try_log(
                            dmk::LogLevel::Debug,
                            "The heartbeat reports {} damage, {} hook calls, and {} combo presses.",
                            damage,
                            s_hook_calls.load(std::memory_order_relaxed),
                            s_combo_presses.load(std::memory_order_relaxed)
                        );
                    }
                }
            );

            // Input start is the final fallible step. Init rollback omits the typed drain, so no later operation can
            // fail with a live poller.
            if (!s_session->input().start(
                    dmk::input::Input::Settings{
                        .wheel_backend = dmk::input::Input::WheelBackend::ExternalHost,
                        .wheel_host = request->wheel_host,
                        .wheel_host_required = true,
                    }
                ))
            {
                roll_back_generation();
                return 0;
            }
            return DMK_STAGED_RELOAD_OK;
        }
        catch (...)
        {
            roll_back_generation();
            return 0;
        }
    }

    /**
     * @brief Retires the generation before the loader releases or retains this image.
     * @return A DetourModKit/abi/staged_reload.h value. BUSY leaves the generation live. REFUSED keeps it mapped after
     *         a failed worker join or callback drain, and a retry can succeed after the drain.
     * @note The loader calls this from its control thread, off the loader lock.
     */
    __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL Shutdown() noexcept
    {
        // The retirement runs first, so a BUSY or Refused result changes nothing that the generation needs.
        const dmk::hook::HookRetirement retirement = s_hooks.retire(RETIREMENT_DEADLINE);
        if (retirement.outcome != dmk::hook::RetirementOutcome::Retired)
        {
            return dmk::staged_reload::verdict(retirement, s_baseline, s_loader_abi_version);
        }
        if (!stop_generation_workers())
        {
            return DMK_STAGED_RELOAD_REFUSED;
        }
        if (s_session.has_value())
        {
            // Revert every raw memory::patch_code or write_bytes change here, before the drain. This sample makes none.
            if (dmk::prepare_logic_dll_unload_all() != dmk::LogicDllUnloadStatus::SafeToUnload)
            {
                return DMK_STAGED_RELOAD_REFUSED;
            }
            s_session.reset(); // Ordered teardown can retain XInput here.
        }
        return dmk::staged_reload::verdict(retirement, s_baseline, s_loader_abi_version);
    }
} // extern "C"

/** @brief Prevents Session teardown under the loader lock at process termination. */
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID reserved) noexcept
{
    if (reason == DLL_PROCESS_DETACH && reserved != nullptr && s_session.has_value())
    {
        s_session->abandon();
    }
    return TRUE;
}
