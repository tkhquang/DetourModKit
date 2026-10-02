#include "DetourModKit/hook.hpp"
#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"
#include "internal/input_intercept.hpp"
#include "internal/xinput_raw_scope.hpp"
#include "internal/xinput_route_probe.hpp"

#include <windows.h>
#include <Xinput.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

namespace DetourModKit::detail
{
    extern void (*g_logger_record_probe)(LogLevel, std::string_view) noexcept;
} // namespace DetourModKit::detail

namespace
{
    using XInputGetStateFn = DWORD(WINAPI *)(DWORD, XINPUT_STATE *);
    using SetSuccessStateFn = void(WINAPI *)(BOOL);
    using SetButtonsFn = void(WINAPI *)(WORD);
    using ByteWindow = std::array<unsigned char, 32>;
    using Module = std::unique_ptr<std::remove_pointer_t<HMODULE>, void (*)(HMODULE)>;

    constexpr WORD SUPPRESS_BITS = XINPUT_GAMEPAD_DPAD_UP | XINPUT_GAMEPAD_A;
    constexpr WORD TEN_COPY_SUPPRESS_BITS = SUPPRESS_BITS | XINPUT_GAMEPAD_LEFT_SHOULDER;
    std::atomic<XInputGetStateFn> s_original{nullptr};
    std::atomic<unsigned int> s_primary_entries{0};
    std::atomic<unsigned int> s_foreign_forwards{0};
    std::atomic<unsigned int> s_foreign_bypasses{0};
    DWORD s_probe_thread_id{0};
    XINPUT_STATE s_cached_raw{};

    void release_module(HMODULE module) noexcept
    {
        FreeLibrary(module);
    }

    void note_primary_entry() noexcept
    {
        s_primary_entries.fetch_add(1, std::memory_order_relaxed);
    }

    DWORD WINAPI conditional_handler(DWORD user_index, XINPUT_STATE *state) noexcept
    {
        if (GetCurrentThreadId() != s_probe_thread_id && user_index == 0 && state != nullptr)
        {
            *state = s_cached_raw;
            s_foreign_bypasses.fetch_add(1, std::memory_order_relaxed);
            return ERROR_SUCCESS;
        }
        s_foreign_forwards.fetch_add(1, std::memory_order_relaxed);
        const XInputGetStateFn original = s_original.load(std::memory_order_acquire);
        return original != nullptr ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
    }

    [[nodiscard]] ByteWindow snapshot(void *target) noexcept
    {
        ByteWindow bytes{};
        std::memcpy(bytes.data(), target, bytes.size());
        return bytes;
    }

    [[nodiscard]] bool fields_match(const XINPUT_STATE &state, const XINPUT_STATE &raw, WORD mask) noexcept
    {
        return state.Gamepad.wButtons == static_cast<WORD>(raw.Gamepad.wButtons & ~mask) &&
               state.Gamepad.bLeftTrigger == raw.Gamepad.bLeftTrigger &&
               state.Gamepad.bRightTrigger == raw.Gamepad.bRightTrigger &&
               state.Gamepad.sThumbLX == raw.Gamepad.sThumbLX && state.Gamepad.sThumbLY == raw.Gamepad.sThumbLY &&
               state.Gamepad.sThumbRX == raw.Gamepad.sThumbRX && state.Gamepad.sThumbRY == raw.Gamepad.sThumbRY;
    }

    [[nodiscard]] bool
    matches(const XINPUT_STATE &state, const XINPUT_STATE &raw, DWORD expected_packet, bool masked) noexcept
    {
        return state.dwPacketNumber == expected_packet && fields_match(state, raw, masked ? SUPPRESS_BITS : 0);
    }

    [[nodiscard]] bool require(bool condition, const char *message) noexcept
    {
        if (!condition)
            std::fprintf(stderr, "FAIL: %s\n", message);
        return condition;
    }

    int run_conditional_case(bool conditional_ex)
    {
        using namespace DetourModKit::detail;

        const std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&release_module)> module{
            LoadLibraryW(L"dmk_xinput_proxy_local.dll"),
            &release_module
        };
        if (!require(module != nullptr, "the local fixture must load"))
            return 2;
        auto *const primary_target = reinterpret_cast<void *>(GetProcAddress(module.get(), "XInputGetState"));
        auto *const ex_target = reinterpret_cast<void *>(GetProcAddress(module.get(), MAKEINTRESOURCEA(100)));
        const auto primary = reinterpret_cast<XInputGetStateFn>(primary_target);
        const auto ex = reinterpret_cast<XInputGetStateFn>(ex_target);
        const auto set_success = reinterpret_cast<SetSuccessStateFn>(
            reinterpret_cast<void *>(GetProcAddress(module.get(), "dmk_xinput_set_success_state"))
        );
        if (!require(
                primary != nullptr && ex != nullptr && primary != ex && set_success != nullptr,
                "the fixture must expose both distinct routes and its state control"
            ))
            return 3;

        XINPUT_STATE disconnected_primary{};
        XINPUT_STATE disconnected_ex{};
        if (!require(
                primary(1, &disconnected_primary) == ERROR_DEVICE_NOT_CONNECTED &&
                    ex(1, &disconnected_ex) == ERROR_DEVICE_NOT_CONNECTED && disconnected_primary.dwPacketNumber == 1 &&
                    disconnected_ex.dwPacketNumber == 2,
                "the default fixture behavior must stay unchanged"
            ))
            return 4;
        set_success(TRUE);
        const std::array<XInputGetStateFn, 2> routes{primary, ex};
        const std::array<void *, 2> targets{primary_target, ex_target};
        const std::array<ByteWindow, 2> original_bytes{snapshot(primary_target), snapshot(ex_target)};
        std::array<std::array<XINPUT_STATE, 2>, 2> raw{};
        std::array<std::array<DWORD, 2>, 2> next_packet{};
        for (std::size_t route = 0; route < routes.size(); ++route)
        {
            for (DWORD user_index = 0; user_index < 2; ++user_index)
            {
                if (!require(
                        routes[route](user_index, &raw[route][user_index]) == ERROR_SUCCESS,
                        "the successful fixture state must establish the raw baseline"
                    ))
                    return 5;
                next_packet[route][user_index] = raw[route][user_index].dwPacketNumber + 1;
            }
        }

        const std::size_t conditional_route = conditional_ex ? 1u : 0u;
        s_cached_raw = raw[conditional_route][0];
        s_probe_thread_id = GetCurrentThreadId();
        set_xinput_module_override_for_test(module.get());
        if (!require(install_xinput(0), "the base pair must install"))
            return 6;
        set_xinput_detour_body_seam(&note_primary_entry);
        const XInputGetStateFn saved_primary = xinput_trampoline();
        const XInputGetStateFn saved_ex = xinput_ex_trampoline();

        DetourModKit::hook::InlineRequest request{
            .name = "XInputConditionalCoverage",
            .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(targets[conditional_route])},
            .options = {.prologue = DetourModKit::hook::Prologue::Relocate},
        };
        auto layered = DetourModKit::hook::inline_at(std::move(request), &conditional_handler);
        if (!require(layered.has_value(), "the conditional layer must use a real saved original"))
            return 7;
        std::optional<DetourModKit::hook::Hook> newer{std::move(*layered)};
        s_original.store(newer->original<XInputGetStateFn>(), std::memory_order_release);
        if (!require(newer->enable().has_value(), "the conditional layer must arm"))
            return 8;
        const std::array<ByteWindow, 2> layered_bytes{snapshot(primary_target), snapshot(ex_target)};

        const auto sample_pair = [&routes, &raw, &next_packet](bool masked) -> bool
        {
            if (masked && !DetourModKit::detail::publish_gamepad_suppress(SUPPRESS_BITS, STANDALONE_INTERCEPT_OWNER))
                return false;
            for (std::size_t route = 0; route < routes.size(); ++route)
            {
                XINPUT_STATE sampled{};
                if (routes[route](0, &sampled) != ERROR_SUCCESS || sampled.dwPacketNumber < next_packet[route][0] ||
                    !fields_match(sampled, raw[route][0], masked ? SUPPRESS_BITS : 0))
                    return false;
                next_packet[route][0] = sampled.dwPacketNumber + 1;
            }
            return true;
        };
        if (!require(sample_pair(true), "the probe thread must receive masked states from both routes"))
            return 9;
        if (!require(
                s_primary_entries.load(std::memory_order_relaxed) == 1 &&
                    s_foreign_forwards.load(std::memory_order_relaxed) == 1,
                "the positive sample must enter the primary detour and the saved original"
            ))
            return 10;

        std::array<std::array<XINPUT_STATE, 2>, 2> game_states{};
        std::array<std::array<DWORD, 2>, 2> game_results{};
        const unsigned int entries_before_game = s_primary_entries.load(std::memory_order_relaxed);
        std::thread game_thread(
            [routes, &game_states, &game_results]() -> void
            {
                for (std::size_t route = 0; route < routes.size(); ++route)
                {
                    for (DWORD user_index = 0; user_index < 2; ++user_index)
                        game_results[route][user_index] = routes[route](user_index, &game_states[route][user_index]);
                }
            }
        );
        game_thread.join();
        for (std::size_t route = 0; route < routes.size(); ++route)
        {
            for (DWORD user_index = 0; user_index < 2; ++user_index)
            {
                const bool bypass = route == conditional_route && user_index == 0;
                const DWORD packet = bypass ? s_cached_raw.dwPacketNumber : next_packet[route][user_index]++;
                if (!require(
                        game_results[route][user_index] == ERROR_SUCCESS && matches(
                                                                                game_states[route][user_index],
                                                                                raw[route][user_index],
                                                                                packet,
                                                                                !bypass && user_index == 0
                                                                            ),
                        "the game thread must bypass one member and preserve the companion and other user"
                    ))
                    return 11;
            }
        }
        if (!require(
                s_foreign_bypasses.load(std::memory_order_relaxed) == 1 &&
                    s_foreign_forwards.load(std::memory_order_relaxed) == 2 &&
                    s_primary_entries.load(std::memory_order_relaxed) ==
                        entries_before_game + (conditional_ex ? 2u : 1u),
                "the cached route must skip the saved original only for the bound game-thread user"
            ))
            return 12;
        if (!require(
                sample_pair(true) && layered_bytes[0] == snapshot(primary_target) &&
                    layered_bytes[1] == snapshot(ex_target) && xinput_installed() &&
                    xinput_trampoline() == saved_primary && xinput_ex_trampoline() == saved_ex,
                "both probe samples must stay masked with unchanged bytes and original storage"
            ))
            return 13;

        if (!require(
                install_xinput(0) && xinput_installed() && !xinput_pair_degraded_for_test(),
                "successful scoped receipts must publish observed health for the probe thread"
            ))
            return 14;
        const auto exact = xinput_pair_coverage_for_test();
        const auto observed = xinput_pair_observation_for_test();
        if (!require(
                conditional_ex ? (!exact.ex && observed.ex) : (!exact.primary && observed.primary),
                "a foreign entry must use observed evidence without a false exact-patch claim"
            ))
            return 14;
        if (!require(
                sample_pair(true) && layered_bytes[0] == snapshot(primary_target) &&
                    layered_bytes[1] == snapshot(ex_target),
                "observed health must preserve the same bytes and the scoped sample behavior"
            ))
            return 15;
        std::array<XINPUT_STATE, 2> observed_game{};
        std::array<DWORD, 2> observed_results{};
        std::thread observed_game_thread(
            [routes, &observed_game, &observed_results]() -> void
            {
                for (std::size_t route = 0; route < routes.size(); ++route)
                    observed_results[route] = routes[route](0, &observed_game[route]);
            }
        );
        observed_game_thread.join();
        for (std::size_t route = 0; route < routes.size(); ++route)
        {
            if (!require(
                    observed_results[route] == ERROR_SUCCESS && fields_match(
                                                                    observed_game[route],
                                                                    raw[route][0],
                                                                    route == conditional_route ? 0 : SUPPRESS_BITS
                                                                ),
                    "an observed receipt must not claim that every game-thread branch traverses DMK"
                ))
                return 15;
            if (route != conditional_route)
                next_packet[route][0] = observed_game[route].dwPacketNumber + 1;
        }
        if (!require(
                xinput_installed() && layered_bytes[0] == snapshot(primary_target) &&
                    layered_bytes[1] == snapshot(ex_target),
                "the conditional limit must require no byte change"
            ))
            return 15;

        if (!require(newer->disable().has_value(), "the conditional layer must hand back the owned patch"))
            return 16;
        s_original.store(nullptr, std::memory_order_release);
        newer.reset();
        if (!require(
                install_xinput(0) && xinput_installed() && xinput_trampoline() == saved_primary &&
                    xinput_ex_trampoline() == saved_ex && sample_pair(true),
                "hand-back must recover both masks through the same original storage"
            ))
            return 17;
        set_xinput_detour_body_seam(nullptr);
        uninstall();
        if (!require(
                !xinput_installed() && original_bytes[0] == snapshot(primary_target) &&
                    original_bytes[1] == snapshot(ex_target) && xinput_module_refs_held() == 0 && sample_pair(false),
                "clean teardown must restore both prologues and balance the module references"
            ))
            return 18;
        set_xinput_module_override_for_test(nullptr);
        std::printf(
            "PASS: conditional %s disproves sampled pair coverage with unchanged bytes\n",
            conditional_ex ? "Ex" : "primary"
        );
        return 0;
    }

    struct Provider
    {
        Module module{nullptr, &release_module};
        std::array<XInputGetStateFn, 2> routes{};
        std::array<void *, 2> targets{};
        std::array<ByteWindow, 2> original_bytes{};
        std::array<std::array<XINPUT_STATE, 2>, 2> raw{};
        SetButtonsFn set_buttons{nullptr};
        SetSuccessStateFn set_success{nullptr};

        [[nodiscard]] bool prepare() noexcept
        {
            module.reset(LoadLibraryW(L"dmk_xinput_proxy_local.dll"));
            if (!module)
                return false;
            targets[0] = reinterpret_cast<void *>(GetProcAddress(module.get(), "XInputGetState"));
            targets[1] = reinterpret_cast<void *>(GetProcAddress(module.get(), MAKEINTRESOURCEA(100)));
            set_success = reinterpret_cast<SetSuccessStateFn>(
                reinterpret_cast<void *>(GetProcAddress(module.get(), "dmk_xinput_set_success_state"))
            );
            set_buttons = reinterpret_cast<SetButtonsFn>(
                reinterpret_cast<void *>(GetProcAddress(module.get(), "dmk_xinput_set_buttons"))
            );
            if (targets[0] == nullptr || targets[1] == nullptr || targets[0] == targets[1] || set_success == nullptr ||
                set_buttons == nullptr)
                return false;
            set_success(TRUE);
            for (std::size_t route = 0; route < routes.size(); ++route)
            {
                routes[route] = reinterpret_cast<XInputGetStateFn>(targets[route]);
                original_bytes[route] = snapshot(targets[route]);
                for (DWORD user_index = 0; user_index < 2; ++user_index)
                {
                    if (routes[route](user_index, &raw[route][user_index]) != ERROR_SUCCESS)
                        return false;
                }
            }
            return true;
        }
    };

    enum class LayerMode
    {
        Forward,
        Bypass,
        BypassDisconnected,
        Park,
        Transform,
        Disconnected,
        ReturnedError,
        InvalidFunction,
        ThrowAfterReceipt,
    };

    std::array<std::atomic<XInputGetStateFn>, 2> s_layer_original{};
    std::array<std::atomic<LayerMode>, 2> s_layer_mode{};
    std::array<std::atomic<unsigned int>, 2> s_layer_returns{};
    std::array<std::array<XINPUT_STATE, 2>, 2> s_layer_raw{};
    std::atomic<bool> s_parked{false};
    std::atomic<unsigned int> s_park_count{0};
    std::atomic<bool> s_release_park{false};
    std::atomic<bool> s_parked_call_raw_success{false};

    DWORD layer_call(std::size_t route, DWORD user_index, XINPUT_STATE *state)
    {
        const LayerMode mode = s_layer_mode[route].load(std::memory_order_relaxed);
        if (mode == LayerMode::BypassDisconnected)
            return ERROR_DEVICE_NOT_CONNECTED;
        if (mode == LayerMode::Bypass && state != nullptr && user_index < 2)
        {
            *state = s_layer_raw[route][user_index];
            return ERROR_SUCCESS;
        }
        if (mode == LayerMode::Park && GetCurrentThreadId() != s_probe_thread_id)
        {
            s_parked.store(true, std::memory_order_release);
            s_park_count.fetch_add(1, std::memory_order_release);
            while (!s_release_park.load(std::memory_order_acquire))
                std::this_thread::yield();
        }
        const XInputGetStateFn original = s_layer_original[route].load(std::memory_order_acquire);
        const DWORD result = original != nullptr ? original(user_index, state) : ERROR_DEVICE_NOT_CONNECTED;
        if (mode == LayerMode::Transform && result == ERROR_SUCCESS && state != nullptr && user_index == 0)
            state->Gamepad.wButtons = static_cast<WORD>(state->Gamepad.wButtons & ~XINPUT_GAMEPAD_LEFT_SHOULDER);
        s_layer_returns[route].fetch_add(1, std::memory_order_relaxed);
        if (mode == LayerMode::Park && GetCurrentThreadId() != s_probe_thread_id)
        {
            s_parked_call_raw_success.store(
                result == ERROR_SUCCESS && state != nullptr && fields_match(*state, s_layer_raw[route][0], 0),
                std::memory_order_release
            );
        }
        if (mode == LayerMode::Disconnected)
            return ERROR_DEVICE_NOT_CONNECTED;
        if (mode == LayerMode::ReturnedError)
            return ERROR_ACCESS_DENIED;
        if (mode == LayerMode::InvalidFunction)
            return ERROR_INVALID_FUNCTION;
        // The saved-original call already returned, so the exception crosses only compiler-owned frames.
        if (mode == LayerMode::ThrowAfterReceipt)
            throw 1;
        return result;
    }

    DWORD WINAPI primary_layer(DWORD user_index, XINPUT_STATE *state)
    {
        return layer_call(0, user_index, state);
    }

    DWORD WINAPI ex_layer(DWORD user_index, XINPUT_STATE *state)
    {
        return layer_call(1, user_index, state);
    }

    [[nodiscard]] std::optional<DetourModKit::hook::Hook>
    install_layer(Provider &provider, std::size_t route, LayerMode mode)
    {
        s_layer_raw[route] = provider.raw[route];
        s_layer_mode[route].store(mode, std::memory_order_relaxed);
        s_layer_returns[route].store(0, std::memory_order_relaxed);
        DetourModKit::hook::InlineRequest request{
            .name = route == 0 ? "XInputPrimaryLayer" : "XInputExLayer",
            .target = DetourModKit::Address{reinterpret_cast<std::uintptr_t>(provider.targets[route])},
            .options = {.prologue = DetourModKit::hook::Prologue::Relocate},
        };
        auto created = DetourModKit::hook::inline_at(std::move(request), route == 0 ? &primary_layer : &ex_layer);
        if (!created)
            return std::nullopt;
        std::optional<DetourModKit::hook::Hook> layer{std::move(*created)};
        s_layer_original[route].store(layer->original<XInputGetStateFn>(), std::memory_order_release);
        if (!layer->enable())
            return std::nullopt;
        return layer;
    }

    template <class Predicate> [[nodiscard]] bool wait_for(Predicate predicate)
    {
        const ULONGLONG deadline = GetTickCount64() + 5000;
        do
        {
            if (predicate())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        } while (GetTickCount64() < deadline);
        return false;
    }

    [[nodiscard]] bool
    check_provider(Provider &provider, WORD mask, const std::optional<std::size_t> &bypass = std::nullopt)
    {
        for (std::size_t route = 0; route < provider.routes.size(); ++route)
        {
            XINPUT_STATE first{};
            XINPUT_STATE second{};
            XINPUT_STATE other_user{};
            if (provider.routes[route](0, &first) != ERROR_SUCCESS ||
                provider.routes[route](0, &second) != ERROR_SUCCESS ||
                provider.routes[route](1, &other_user) != ERROR_SUCCESS ||
                !fields_match(first, provider.raw[route][0], mask) ||
                !fields_match(second, provider.raw[route][0], mask) ||
                !fields_match(other_user, provider.raw[route][1], 0) ||
                ((!bypass || *bypass != route) && second.dwPacketNumber <= first.dwPacketNumber))
                return false;
        }
        return true;
    }

    void stop_input(DetourModKit::input::Input *input) noexcept
    {
        input->shutdown();
    }

    int run_layered_binding_case(std::string_view scenario)
    {
        using namespace DetourModKit::detail;
        Provider provider;
        if (!require(provider.prepare(), "the layered fixture must supply independent successful states"))
            return 20;
        set_xinput_module_override_for_test(provider.module.get());
        const bool disconnected_start = scenario == "disconnected-startup";
        if (disconnected_start)
            provider.set_success(FALSE);
        auto &input = DetourModKit::input::Input::instance();
        std::atomic<bool> held{false};
        auto guard = input.register_combo({
            .name = "layered_consume",
            .trigger = DetourModKit::input::Trigger::Hold,
            .combos = {{
                .keys = {DetourModKit::gamepad_button(XINPUT_GAMEPAD_DPAD_UP)},
                .modifiers = {DetourModKit::gamepad_button(XINPUT_GAMEPAD_LEFT_SHOULDER)},
            }},
            .consume = true,
            .on_state_change = [&held](bool active) -> void { held.store(active, std::memory_order_release); },
        });
        const std::unique_ptr<DetourModKit::input::Input, decltype(&stop_input)> shutdown{&input, &stop_input};
        if (!require(
                guard.has_value() &&
                    input.start({.poll_interval = std::chrono::milliseconds{2}, .require_focus = false}).has_value() &&
                    wait_for([]() -> bool { return xinput_installed(); }),
                "the poller must install the pair even before the controller connects"
            ))
            return 21;
        if (!disconnected_start &&
            !require(
                wait_for([&input, &held]() -> bool { return input.is_active("layered_consume") && held.load(); }) &&
                    check_provider(provider, XINPUT_GAMEPAD_DPAD_UP),
                "the base layer must detect the raw chord and preserve every other field"
            ))
            return 22;

        const bool nonforwarding = scenario.starts_with("nonforwarding");
        const bool primary_selected = disconnected_start || scenario.ends_with("primary") || scenario.ends_with("both");
        const bool ex_selected = disconnected_start || scenario.ends_with("ex") || scenario.ends_with("both");
        const LayerMode mode = nonforwarding ? LayerMode::Bypass : LayerMode::Forward;
        std::array<std::optional<DetourModKit::hook::Hook>, 2> layers;
        if (primary_selected)
            layers[0] = install_layer(provider, 0, mode);
        if (ex_selected)
            layers[1] = install_layer(provider, 1, mode);
        if (!require((!primary_selected || layers[0]) && (!ex_selected || layers[1]), "the ordinary handlers must arm"))
            return 23;
        const std::array<ByteWindow, 2> layered_bytes{snapshot(provider.targets[0]), snapshot(provider.targets[1])};
        if (disconnected_start)
        {
            if (!require(
                    wait_for([]() -> bool { return !xinput_installed() && xinput_pair_degraded_for_test(); }) &&
                        !input.is_active("layered_consume") && !held.load(),
                    "disconnected foreign routes must keep the chord inactive and suppression disarmed"
                ))
                return 24;
            provider.set_success(TRUE);
            if (!require(
                    wait_for(
                        [&input, &held]() -> bool
                        { return xinput_installed() && input.is_active("layered_consume") && held.load(); }
                    ),
                    "connection must recover the same hooks and the raw chord without a restart"
                ))
                return 24;
        }
        const bool expected_installed = !nonforwarding;
        if (!require(
                wait_for(
                    [expected_installed, primary_selected, ex_selected]() -> bool
                    {
                        return xinput_installed() == expected_installed &&
                               (!expected_installed ||
                                ((!primary_selected || s_layer_returns[0].load(std::memory_order_relaxed) >= 2) &&
                                 (!ex_selected || s_layer_returns[1].load(std::memory_order_relaxed) >= 2)));
                    }
                ),
                "the poller must maintain the paired route evidence"
            ))
            return 24;
        std::this_thread::sleep_for(std::chrono::milliseconds{30});
        const std::optional<std::size_t> bypass =
            nonforwarding ? std::optional<std::size_t>{ex_selected ? 1u : 0u} : std::nullopt;
        if (!require(
                xinput_installed() == expected_installed &&
                    check_provider(provider, nonforwarding ? 0 : XINPUT_GAMEPAD_DPAD_UP, bypass) &&
                    layered_bytes[0] == snapshot(provider.targets[0]) &&
                    layered_bytes[1] == snapshot(provider.targets[1]),
                "forwarders must keep consume and a real bypass must disarm both without a byte write"
            ))
            return 25;
        if (!nonforwarding && !require(
                                  input.is_active("layered_consume") && held.load(),
                                  "the forwarded chord must stay visible to raw poll samples"
                              ))
            return 26;
        if (!nonforwarding)
        {
            const auto exact = xinput_pair_coverage_for_test();
            const auto observed = xinput_pair_observation_for_test();
            if (!require(
                    (!primary_selected || (!exact.primary && observed.primary)) &&
                        (!ex_selected || (!exact.ex && observed.ex)),
                    "each foreign forwarder must use observed evidence separately from exact ownership"
                ))
                return 26;
        }
        const XInputGetStateFn saved_primary = xinput_trampoline();
        const XInputGetStateFn saved_ex = xinput_ex_trampoline();
        input.shutdown();
        guard->release();
        XINPUT_STATE saved_primary_state{};
        XINPUT_STATE saved_ex_state{};
        if (!require(
                !xinput_installed() && xinput_module_refs_held() == 2 && xinput_trampoline() == nullptr &&
                    xinput_ex_trampoline() == saved_ex && saved_primary(0, &saved_primary_state) == ERROR_SUCCESS &&
                    fields_match(saved_primary_state, provider.raw[0][0], 0) &&
                    saved_ex(0, &saved_ex_state) == ERROR_SUCCESS &&
                    fields_match(saved_ex_state, provider.raw[1][0], 0) && check_provider(provider, 0, bypass) &&
                    layered_bytes[0] == snapshot(provider.targets[0]) &&
                    layered_bytes[1] == snapshot(provider.targets[1]),
                "teardown under a newer handler must retain both raw chains after the poller joins"
            ))
            return 27;
        for (std::size_t route = layers.size(); route-- > 0;)
        {
            if (layers[route] && !require(layers[route]->disable().has_value(), "the ordinary handler must hand back"))
                return 27;
            layers[route].reset();
            s_layer_original[route].store(nullptr, std::memory_order_release);
        }
        if (!require(
                install_xinput(0) && xinput_trampoline() == saved_primary && xinput_ex_trampoline() == saved_ex &&
                    publish_gamepad_suppress(XINPUT_GAMEPAD_DPAD_UP, STANDALONE_INTERCEPT_OWNER) &&
                    check_provider(provider, XINPUT_GAMEPAD_DPAD_UP),
                "hand-back must restore both consumed routes"
            ))
            return 28;
        uninstall();
        if (!require(
                !xinput_installed() && xinput_module_refs_held() == 2 && check_provider(provider, 0),
                "retained route storage must keep both providers raw after the final disarm"
            ))
            return 29;
        set_xinput_module_override_for_test(nullptr);
        return 0;
    }

    struct Copy
    {
        using Start = BOOL(WINAPI *)(HMODULE, DWORD);
        using Query = BOOL(WINAPI *)();
        using References = DWORD(WINAPI *)();
        using Stop = void(WINAPI *)();
        Module module{nullptr, &release_module};
        Start start{nullptr};
        Query active{nullptr};
        Query installed{nullptr};
        Stop stop{nullptr};
        References references{nullptr};
        References evidence{nullptr};
        References edges{nullptr};
        Start start_rules{nullptr};
        Query refresh_rules{nullptr};
    };

    template <class Fn> [[nodiscard]] Fn resolve(HMODULE module, const char *name) noexcept
    {
        return reinterpret_cast<Fn>(reinterpret_cast<void *>(GetProcAddress(module, name)));
    }

    [[nodiscard]] bool load_copy(Copy &copy, std::size_t index) noexcept
    {
        std::array<wchar_t, 64> name{};
        const int name_length = std::swprintf(
            name.data(),
            name.size(),
            L"dmk_xinput_consume_copy_%u.dll",
            static_cast<unsigned int>(index)
        );
        if (name_length < 0)
            return false;
        copy.module.reset(LoadLibraryW(name.data()));
        if (!copy.module)
            return false;
        copy.start = resolve<Copy::Start>(copy.module.get(), "dmk_xinput_copy_start");
        copy.active = resolve<Copy::Query>(copy.module.get(), "dmk_xinput_copy_active");
        copy.installed = resolve<Copy::Query>(copy.module.get(), "dmk_xinput_copy_installed");
        copy.stop = resolve<Copy::Stop>(copy.module.get(), "dmk_xinput_copy_stop");
        copy.references = resolve<Copy::References>(copy.module.get(), "dmk_xinput_copy_module_refs");
        copy.evidence = resolve<Copy::References>(copy.module.get(), "dmk_xinput_copy_evidence");
        copy.edges = resolve<Copy::References>(copy.module.get(), "dmk_xinput_copy_edges");
        copy.start_rules = resolve<Copy::Start>(copy.module.get(), "dmk_xinput_copy_start_rules");
        copy.refresh_rules = resolve<Copy::Query>(copy.module.get(), "dmk_xinput_copy_refresh_rules");
        return copy.start && copy.active && copy.installed && copy.stop && copy.references && copy.evidence &&
               copy.edges && copy.start_rules && copy.refresh_rules;
    }

    int run_ten_copies(bool reverse)
    {
        Provider provider;
        if (!require(provider.prepare(), "the ten-copy fixture must supply successful states"))
            return 30;
        std::array<Copy, 10> copies;
        std::optional<DetourModKit::hook::Hook> relay;
        for (std::size_t order = 0; order < copies.size(); ++order)
        {
            const std::size_t index = reverse ? copies.size() - 1 - order : order;
            Copy &copy = copies[order];
            if (!require(load_copy(copy, index), "each static copy DLL must load with its complete proof API"))
                return 31;
            if (!require(
                    copy.start(
                        provider.module.get(),
                        index == 0 ? XINPUT_GAMEPAD_LEFT_SHOULDER
                                   : (index % 2 == 0 ? XINPUT_GAMEPAD_DPAD_UP : XINPUT_GAMEPAD_A)
                    ) && wait_for([&copy]() -> bool { return copy.active() && copy.installed(); }),
                    "each independent poller must observe its complete raw chord"
                ))
                return 32;
            if (order == 4)
            {
                relay = install_layer(provider, 0, LayerMode::Forward);
                if (!require(relay.has_value(), "an ordinary overlay relay must separate the static copies"))
                    return 33;
            }
        }
        if (!require(
                wait_for(
                    [&copies]() -> bool
                    {
                        for (const auto &copy : copies)
                        {
                            if (!copy.active() || !copy.installed())
                                return false;
                        }
                        return true;
                    }
                ) && check_provider(provider, TEN_COPY_SUPPRESS_BITS),
                "all ten raw pollers must stay active while the game receives the union of their consume masks"
            ))
            return 34;
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        for (const auto &copy : copies)
        {
            if (!require(
                    copy.active() && copy.installed(),
                    "an inner poller must not receive an outer copy's masked state"
                ))
                return 35;
        }
        for (std::size_t order = 0; order < copies.size(); ++order)
        {
            const DWORD evidence = copies[order].evidence();
            if (!require(
                    order == copies.size() - 1 ? (evidence & 3u) == 3u : (evidence & 15u) == 12u,
                    "inner static copies must distinguish observed coverage from the top copy's exact patches"
                ))
                return 35;
        }
        std::array<DWORD, 10> edges_before{};
        for (std::size_t order = 0; order < copies.size(); ++order)
            edges_before[order] = copies[order].edges();
        provider.set_buttons(XINPUT_GAMEPAD_B);
        if (!require(
                wait_for(
                    [&copies, &edges_before]() -> bool
                    {
                        for (std::size_t order = 0; order < copies.size(); ++order)
                        {
                            if (copies[order].active() || copies[order].edges() <= edges_before[order])
                                return false;
                        }
                        return true;
                    }
                ),
                "every inner copy must observe a fresh raw release after the complete chain exists"
            ))
            return 35;
        provider.set_buttons(provider.raw[0][0].Gamepad.wButtons);
        if (!require(
                wait_for(
                    [&copies, &edges_before]() -> bool
                    {
                        for (std::size_t order = 0; order < copies.size(); ++order)
                        {
                            if (!copies[order].active() || !copies[order].installed() ||
                                copies[order].edges() < edges_before[order] + 2)
                                return false;
                        }
                        return true;
                    }
                ) && check_provider(provider, TEN_COPY_SUPPRESS_BITS),
                "every inner copy must observe a fresh raw chord despite all outer consume masks"
            ))
            return 35;
        DWORD retained_references{0};
        for (std::size_t order = copies.size(); order-- > 0;)
        {
            copies[order].stop();
            const DWORD references = copies[order].references();
            retained_references += references;
            if (!require(
                    !copies[order].active() && !copies[order].installed() &&
                        (order < 5 ? references == 2 : (references == 0 || references == 2)),
                    "joined copies must retain only the chains beneath the newer overlay relay"
                ))
                return 36;
        }
        if (!require(relay->disable().has_value(), "the overlay relay must hand back after every poller joins"))
            return 36;
        relay.reset();
        s_layer_original[0].store(nullptr, std::memory_order_release);
        if (!require(
                check_provider(provider, 0),
                "ten shutdowns must leave both successful providers raw through the retained inner chains"
            ))
            return 37;
        std::printf(
            "PASS: ten copies %s report %lu retained provider references after joined shutdown\n",
            reverse ? "reverse" : "forward",
            retained_references
        );
        return 0;
    }

    int run_two_copy_first_frame(bool reverse)
    {
        Provider provider;
        if (!require(provider.prepare(), "the first-frame fixture must supply independent successful states"))
            return 60;
        std::array<Copy, 2> copies;
        std::optional<DetourModKit::hook::Hook> relay;
        for (std::size_t order = 0; order < copies.size(); ++order)
        {
            const std::size_t index = reverse ? copies.size() - 1 - order : order;
            if (!require(
                    load_copy(copies[order], index) &&
                        copies[order].start_rules(provider.module.get(), static_cast<DWORD>(index)),
                    "each copy must arm only its same-frame rule with a zero reactive mask"
                ))
                return 61;
            if (order == 0)
            {
                relay = install_layer(provider, 0, LayerMode::Forward);
                if (!require(relay.has_value(), "an ordinary overlay handler must separate the first-frame copies"))
                    return 62;
            }
        }
        for (const auto &copy : copies)
        {
            if (!require(
                    copy.refresh_rules() && copy.installed() && copy.edges() == 0,
                    "route refresh must keep the reactive mask zero without any poller delivery"
                ))
                return 63;
        }
        if (!require(
                (copies[0].evidence() & 15u) == 12u && (copies[1].evidence() & 3u) == 3u &&
                    check_provider(provider, XINPUT_GAMEPAD_LEFT_SHOULDER | XINPUT_GAMEPAD_A),
                "the first game read must evaluate both rules against the original modifier bits"
            ))
            return 64;
        for (std::size_t order = copies.size(); order-- > 0;)
            copies[order].stop();
        if (!require(
                copies[0].references() == 2 && copies[1].references() == 0 && relay->disable().has_value(),
                "quiescent teardown must preserve only the lower foreign chain"
            ))
            return 65;
        relay.reset();
        s_layer_original[0].store(nullptr, std::memory_order_release);
        if (!require(check_provider(provider, 0), "both rule-only copies must stop all masking after teardown"))
            return 66;
        return 0;
    }

    int run_transforming_forwarder()
    {
        Provider provider;
        if (!require(provider.prepare(), "the transforming fixture must supply independent successful states"))
            return 70;
        std::array<Copy, 2> copies;
        if (!require(
                load_copy(copies[0], 0) && copies[0].start_rules(provider.module.get(), 2),
                "the lower copy must consume only UP through a same-frame rule"
            ))
            return 71;
        std::array<std::optional<DetourModKit::hook::Hook>, 2> layers;
        for (std::size_t route = 0; route < layers.size(); ++route)
        {
            layers[route] = install_layer(provider, route, LayerMode::Transform);
            if (!require(layers[route].has_value(), "both ordinary handlers must clear LB after their saved original"))
                return 72;
        }
        const std::array<ByteWindow, 2> foreign_bytes{snapshot(provider.targets[0]), snapshot(provider.targets[1])};
        if (!require(
                load_copy(copies[1], 1) && copies[1].start_rules(provider.module.get(), 1),
                "the upper copy must publish LB+A with a zero reactive mask and no poller"
            ))
            return 73;
        for (const auto &copy : copies)
        {
            if (!require(
                    copy.refresh_rules() && copy.installed() && copy.edges() == 0,
                    "route refresh must preserve the rule-only zero-mask state"
                ))
                return 74;
        }
        constexpr WORD transformed_mask = XINPUT_GAMEPAD_DPAD_UP | XINPUT_GAMEPAD_LEFT_SHOULDER;
        if (!require(
                (copies[0].evidence() & 15u) == 12u && (copies[1].evidence() & 3u) == 3u &&
                    check_provider(provider, transformed_mask),
                "a foreign LB removal must preserve A while the lower compatible copy consumes UP"
            ))
            return 75;
        for (std::size_t order = copies.size(); order-- > 0;)
            copies[order].stop();
        if (!require(
                copies[0].references() == 2 && copies[1].references() == 0 &&
                    check_provider(provider, XINPUT_GAMEPAD_LEFT_SHOULDER) &&
                    foreign_bytes[0] == snapshot(provider.targets[0]) &&
                    foreign_bytes[1] == snapshot(provider.targets[1]),
                "quiescent shutdown must retain the lower chains and preserve only the foreign LB removal"
            ))
            return 76;
        for (std::size_t route = layers.size(); route-- > 0;)
        {
            if (!require(layers[route]->disable().has_value(), "each transforming handler must hand back its bytes"))
                return 77;
            layers[route].reset();
            s_layer_original[route].store(nullptr, std::memory_order_release);
        }
        if (!require(check_provider(provider, 0), "the retained providers must return every raw bit after hand-back"))
            return 78;
        return 0;
    }

    std::atomic<unsigned int> s_pair_warnings{0};
    std::atomic<bool> s_warning_reentry_succeeded{false};
    std::atomic<bool> s_warning_names_member{true};
    std::atomic<unsigned int> s_pair_recoveries{0};
    std::atomic<bool> s_recovery_reentry_succeeded{false};
    std::array<char, 1024> s_last_warning{};
    std::size_t s_last_warning_length{0};
    std::array<char, 128> s_last_recovery{};
    std::size_t s_last_recovery_length{0};

    void observe_pair_warning(DetourModKit::LogLevel level, std::string_view message) noexcept
    {
        using namespace DetourModKit::detail;
        if (level == DetourModKit::LogLevel::Info &&
            message.starts_with("InputIntercept: XInput paired suppression recovered: "))
        {
            (void)xinput_pair_coverage_for_test();
            (void)xinput_pair_observation_for_test();
            s_recovery_reentry_succeeded.store(
                publish_gamepad_suppress(0, STANDALONE_INTERCEPT_OWNER),
                std::memory_order_release
            );
            s_last_recovery_length = message.size();
            if (message.size() <= s_last_recovery.size())
                std::memcpy(s_last_recovery.data(), message.data(), message.size());
            s_pair_recoveries.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (level != DetourModKit::LogLevel::Warning ||
            !message.starts_with("InputIntercept: XInput paired suppression stopped: "))
            return;
        s_last_warning_length = message.size();
        if (message.size() <= s_last_warning.size())
            std::memcpy(s_last_warning.data(), message.data(), message.size());
        (void)xinput_pair_coverage_for_test();
        (void)xinput_pair_observation_for_test();
        s_warning_reentry_succeeded.store(
            publish_gamepad_suppress(0, STANDALONE_INTERCEPT_OWNER),
            std::memory_order_release
        );
        if (!message.contains("XInputGetState:") || !message.contains("another writer owns the prologue"))
            s_warning_names_member.store(false, std::memory_order_relaxed);
        s_pair_warnings.fetch_add(1, std::memory_order_relaxed);
    }

    int run_route_diagnostics()
    {
        using namespace DetourModKit::detail;
        Provider provider;
        if (!require(provider.prepare(), "the diagnostic fixture must load"))
            return 50;
        set_xinput_module_override_for_test(provider.module.get());
        if (!require(install_xinput(0), "the diagnostic pair must install"))
            return 51;
        auto layer = install_layer(provider, 0, LayerMode::Forward);
        if (!require(layer && install_xinput(0), "the ordinary diagnostic route must supply observed coverage"))
            return 52;
        const auto old_probe = g_logger_record_probe;
        g_logger_record_probe = &observe_pair_warning;
        s_layer_mode[0].store(LayerMode::Bypass, std::memory_order_relaxed);
        for (int cycle = 0; cycle < 32; ++cycle)
        {
            if (!require(!install_xinput(0), "a nonforwarder must stay degraded throughout its episode"))
                return 53;
        }
        if (!require(
                s_pair_warnings.load(std::memory_order_relaxed) == 1 &&
                    s_warning_reentry_succeeded.load(std::memory_order_acquire) &&
                    s_warning_names_member.load(std::memory_order_relaxed),
                "one warning must name the failure after every DMK lock releases"
            ))
            return 54;
        s_layer_mode[0].store(LayerMode::Forward, std::memory_order_relaxed);
        if (!require(install_xinput(0), "a successful observed route must reset the warning episode"))
            return 55;
        for (int cycle = 0; cycle < 32; ++cycle)
        {
            if (!require(install_xinput(0), "healthy retries must keep authorization"))
                return 55;
        }
        if (!require(
                s_pair_recoveries.load() == 1 && s_recovery_reentry_succeeded.load() &&
                    std::string_view{s_last_recovery.data(), s_last_recovery_length}.contains("authorization=observed"),
                "one observed recovery must permit logger reentry and healthy retries must stay silent"
            ))
            return 55;
        const std::string_view warning{s_last_warning.data(), s_last_warning_length};
        if (!require(
                warning.contains("controller=0") && warning.contains("call=returned result=0, authentication=failed") &&
                    warning.ends_with("authentication=matched."),
                "the successful bypass must report failed authentication without truncation of its companion"
            ))
            return 55;
        s_layer_mode[0].store(LayerMode::Bypass, std::memory_order_relaxed);
        if (!require(
                !install_xinput(0) && s_pair_warnings.load(std::memory_order_relaxed) == 2,
                "a new complete-to-degraded episode must emit exactly one new warning"
            ))
            return 56;
        g_logger_record_probe = old_probe;
        if (!require(layer->disable().has_value(), "the diagnostic handler must hand back"))
            return 57;
        layer.reset();
        s_layer_original[0].store(nullptr, std::memory_order_release);
        uninstall();
        set_xinput_module_override_for_test(nullptr);
        return 0;
    }

    class PairLogObserver
    {
    public:
        PairLogObserver() : m_previous(DetourModKit::detail::g_logger_record_probe)
        {
            DetourModKit::log().set_log_level(DetourModKit::LogLevel::Info);
            DetourModKit::detail::g_logger_record_probe = &observe_pair_warning;
        }
        ~PairLogObserver() noexcept { DetourModKit::detail::g_logger_record_probe = m_previous; }
        PairLogObserver(const PairLogObserver &) = delete;
        PairLogObserver &operator=(const PairLogObserver &) = delete;
        PairLogObserver(PairLogObserver &&) = delete;
        PairLogObserver &operator=(PairLogObserver &&) = delete;

    private:
        void (*m_previous)(DetourModKit::LogLevel, std::string_view) noexcept;
    };

    [[nodiscard]] bool warning_contains(std::string_view expected) noexcept
    {
        return s_last_warning_length < s_last_warning.size() &&
               std::string_view{s_last_warning.data(), s_last_warning_length}.contains(expected);
    }

    [[nodiscard]] bool reported_loss(std::size_t route, LayerMode mode)
    {
        const unsigned int before = s_pair_warnings.load();
        s_layer_mode[route].store(mode);
        for (int cycle = 0; cycle < 8; ++cycle)
        {
            if (DetourModKit::detail::install_xinput(0))
                return false;
        }
        return !DetourModKit::detail::xinput_installed() && DetourModKit::detail::xinput_pair_degraded_for_test() &&
               s_pair_warnings.load() == before + 1;
    }

    [[nodiscard]] bool concurrent_route_probes(std::size_t route, bool expected)
    {
        using namespace DetourModKit::detail;
        s_probe_thread_id = GetCurrentThreadId();
        s_layer_mode[route].store(LayerMode::Park);
        s_park_count.store(0);
        s_release_park.store(false);
        std::array<bool, 2> results{};
        std::thread first([&results]() -> void { results[0] = install_xinput(0); });
        std::thread second([&results]() -> void { results[1] = install_xinput(0); });
        const bool both_parked = wait_for([]() -> bool { return s_park_count.load(std::memory_order_acquire) == 2; });
        s_release_park.store(true, std::memory_order_release);
        first.join();
        second.join();
        s_layer_mode[route].store(LayerMode::Forward);
        return both_parked && results[0] == expected && results[1] == expected;
    }

    [[nodiscard]] bool verify_observed_reconnect(Provider &provider, std::size_t route)
    {
        using namespace DetourModKit::detail;
        provider.set_success(FALSE);
        const unsigned int forwards_before = s_layer_returns[route].load();
        if (!require(concurrent_route_probes(route, false), "concurrent disconnected probes must refuse authorization"))
            return false;
        for (int cycle = 0; cycle < 32; ++cycle)
        {
            if (!require(!install_xinput(0), "disconnected samples must never authorize a foreign route"))
                return false;
        }
        if (!require(
                s_pair_warnings.load() == 1 && s_pair_recoveries.load() == 0 &&
                    warning_contains(
                        "controller=0, pair: admission=passed, raw_scope=passed, raw_restore=passed, "
                        "snapshot=passed, context=passed"
                    ) &&
                    warning_contains("call=returned result=1167, authentication=matched") &&
                    std::string_view{s_last_warning.data(), s_last_warning_length}.ends_with(
                        "result=1167, authentication=matched."
                    ) &&
                    s_layer_returns[route].load() == forwards_before + 34,
                "maintenance must measure both authenticated disconnect results once per warning episode"
            ))
            return false;
        provider.set_success(TRUE);
        if (!require(
                concurrent_route_probes(route, true) && s_pair_recoveries.load() == 1,
                "concurrent reconnect probes must publish exactly one observed recovery"
            ))
            return false;
        return true;
    }

    [[nodiscard]] bool verify_member_diagnostics(std::size_t route)
    {
        using namespace DetourModKit::detail;
        const std::array<LayerMode, 6> modes{
            LayerMode::Disconnected,
            LayerMode::BypassDisconnected,
            LayerMode::ReturnedError,
            LayerMode::Bypass,
            LayerMode::InvalidFunction,
            LayerMode::ThrowAfterReceipt,
        };
        const std::array<std::string_view, 6> outcomes{
            "call=returned result=1167, authentication=matched",
            "call=returned result=1167, authentication=failed",
            "call=returned result=5, authentication=matched",
            "call=returned result=0, authentication=failed",
            "call=returned result=1, authentication=matched",
            "call=exception, authentication=matched",
        };
        for (std::size_t i = 0; i < modes.size(); ++i)
        {
            if (!require(reported_loss(route, modes[i]), "each failed member must disarm the complete pair once"))
                return false;
            const std::string_view warning{s_last_warning.data(), s_last_warning_length};
            const auto member_start = warning.find(route == 0 ? "XInputGetState:" : "XInputGetStateEx:");
            if (!require(member_start != std::string_view::npos, "the failed member must have its own evidence fields"))
                return false;
            const auto member_tail = warning.substr(member_start);
            const auto member = member_tail.substr(0, member_tail.find(". XInputGetStateEx:"));
            if (!require(
                    member.contains(outcomes[i]) && warning.contains("controller=0") &&
                        warning.ends_with("authentication=matched.") ==
                            (route == 0 ||
                             (modes[i] != LayerMode::Bypass && modes[i] != LayerMode::BypassDisconnected)) &&
                        (!member.contains("call=exception") || !member.contains("result=")),
                    "the warning must identify the measured member result and distinguish an exception"
                ))
                return false;
            s_layer_mode[route].store(LayerMode::Forward);
            if (!require(
                    install_xinput(0) && s_pair_recoveries.load() == i + 1,
                    "each restored episode must emit one recovery"
                ))
                return false;
        }
        return true;
    }

    [[nodiscard]] bool verify_recovery_exclusions(
        Provider &provider,
        std::size_t route,
        std::optional<DetourModKit::hook::Hook> &layer,
        unsigned int recoveries
    )
    {
        using namespace DetourModKit::detail;
        const XInputGetStateFn saved_primary = xinput_trampoline();
        const XInputGetStateFn saved_ex = xinput_ex_trampoline();
        if (!require(
                reported_loss(route, LayerMode::Bypass) && layer->disable().has_value(),
                "exact hand-back must follow a reported failure"
            ))
            return false;
        layer.reset();
        const ByteWindow handed_back_bytes = snapshot(provider.targets[route]);
        if (!require(
                install_xinput(0) && s_pair_recoveries.load() == recoveries + 1 &&
                    xinput_trampoline() == saved_primary && xinput_ex_trampoline() == saved_ex &&
                    xinput_pair_coverage_for_test().primary && xinput_pair_coverage_for_test().ex &&
                    !xinput_pair_observation_for_test().primary && !xinput_pair_observation_for_test().ex &&
                    handed_back_bytes == snapshot(provider.targets[route]) &&
                    publish_gamepad_suppress(SUPPRESS_BITS, STANDALONE_INTERCEPT_OWNER) &&
                    check_provider(provider, SUPPRESS_BITS) &&
                    std::string_view{s_last_recovery.data(), s_last_recovery_length}.contains("authorization=exact"),
                "exact hand-back must report one recovery through the existing hook"
            ))
            return false;
        layer = install_layer(provider, route, LayerMode::Forward);
        if (!require(layer && install_xinput(0), "episode exclusions need a live forwarder"))
            return false;
        const unsigned int before_exclusions = s_pair_recoveries.load();
        if (!require(reported_loss(route, LayerMode::Bypass), "controller replacement needs a reported episode"))
            return false;
        s_layer_mode[route].store(LayerMode::Forward);
        if (!require(
                install_xinput(1) && s_pair_recoveries.load() == before_exclusions,
                "controller replacement must not inherit a recovery episode"
            ))
            return false;
        if (!require(
                install_xinput(0) && reported_loss(route, LayerMode::Bypass),
                "owner replacement needs another reported episode"
            ))
            return false;
        uninstall();
        const std::uint64_t successor = next_intercept_owner();
        s_layer_mode[route].store(LayerMode::Forward);
        if (!require(
                adopt_owner_for_test(successor) && install_xinput(0, successor) &&
                    s_pair_recoveries.load() == before_exclusions,
                "a successor owner must not inherit the retired episode"
            ))
            return false;
        uninstall(successor);
        s_layer_mode[route].store(LayerMode::Bypass);
        if (!require(!install_xinput(0), "never-complete retries must stay degraded"))
            return false;
        s_layer_mode[route].store(LayerMode::Forward);
        if (!require(
                install_xinput(0) && s_pair_recoveries.load() == before_exclusions,
                "success after never-complete retries must emit no inherited recovery"
            ))
            return false;
        if (!require(reported_loss(route, LayerMode::Bypass), "teardown needs a reported episode"))
            return false;
        if (!require(layer->disable().has_value(), "the layer must retire before fresh hook installation"))
            return false;
        layer.reset();
        uninstall();
        if (!require(
                install_xinput(0) && s_pair_recoveries.load() == before_exclusions,
                "a new hook epoch must not inherit a recovery episode"
            ))
            return false;
        return true;
    }

    int run_measured_diagnostics(std::string_view scenario)
    {
        using namespace DetourModKit::detail;
        Provider provider;
        const PairLogObserver observer;
        if (!require(provider.prepare(), "the measured fixture must load"))
            return 80;
        set_xinput_module_override_for_test(provider.module.get());
        if (!require(install_xinput(0) && s_pair_recoveries.load() == 0, "initial exact success must emit no recovery"))
            return 81;
        const XInputGetStateFn saved_primary = xinput_trampoline();
        const XInputGetStateFn saved_ex = xinput_ex_trampoline();
        const std::size_t route = scenario == "diagnostics-ex" ? 1u : 0u;
        auto layer = install_layer(provider, route, LayerMode::Forward);
        if (!require(
                layer && install_xinput(0) && s_pair_recoveries.load() == 0,
                "initial observed success must emit no recovery"
            ))
            return 82;
        const std::array<ByteWindow, 2> layered_bytes{snapshot(provider.targets[0]), snapshot(provider.targets[1])};
        if (scenario == "observed-reconnect" ? !verify_observed_reconnect(provider, route)
                                             : !verify_member_diagnostics(route))
            return 83;
        if (!require(
                publish_gamepad_suppress(SUPPRESS_BITS, STANDALONE_INTERCEPT_OWNER) &&
                    check_provider(provider, SUPPRESS_BITS) && xinput_trampoline() == saved_primary &&
                    xinput_ex_trampoline() == saved_ex && layered_bytes[0] == snapshot(provider.targets[0]) &&
                    layered_bytes[1] == snapshot(provider.targets[1]),
                "recovery must preserve foreign bytes, trampolines, packets, other users, and analog fields"
            ))
            return 89;
        const unsigned int recoveries = s_pair_recoveries.load();
        for (int cycle = 0; cycle < 16; ++cycle)
        {
            if (!require(install_xinput(0), "healthy observed retries must succeed"))
                return 90;
        }
        if (!require(
                s_pair_recoveries.load() == recoveries && s_recovery_reentry_succeeded.load(),
                "recovery logs must stay latched and permit observer reentry"
            ))
            return 91;

        if (scenario == "exact-recovery" && !verify_recovery_exclusions(provider, route, layer, recoveries))
            return 92;
        if (scenario == "observed-reconnect")
        {
            DetourModKit::log().shutdown();
            if (!require(reported_loss(route, LayerMode::Bypass), "a dropped warning must still disarm suppression"))
                return 99;
            s_layer_mode[route].store(LayerMode::Forward);
            if (!require(
                    install_xinput(0) && publish_gamepad_suppress(SUPPRESS_BITS, STANDALONE_INTERCEPT_OWNER) &&
                        check_provider(provider, SUPPRESS_BITS),
                    "a dropped recovery log must not affect authorization or exported masking"
                ))
                return 99;
        }
        if (layer)
        {
            if (!require(layer->disable().has_value(), "the layer must hand back the owned patch"))
                return 99;
            layer.reset();
        }
        s_layer_original[route].store(nullptr, std::memory_order_release);
        uninstall();
        if (!require(!xinput_installed() && check_provider(provider, 0), "final teardown must preserve raw exports"))
            return 99;
        set_xinput_module_override_for_test(nullptr);
        return 0;
    }

    [[nodiscard]] bool verify_absent_member_diagnostic()
    {
        using namespace DetourModKit::detail;
        Provider absent;
        absent.module.reset(LoadLibraryW(L"dmk_xinput_proxy_noex.dll"));
        if (!require(absent.module != nullptr, "the absent-ordinal fixture must load"))
            return false;
        absent.targets[0] = reinterpret_cast<void *>(GetProcAddress(absent.module.get(), "XInputGetState"));
        if (!require(
                absent.targets[0] != nullptr && GetProcAddress(absent.module.get(), MAKEINTRESOURCEA(100)) == nullptr,
                "the fixture must have only the primary member"
            ))
            return false;
        const ByteWindow original_bytes = snapshot(absent.targets[0]);
        set_xinput_module_override_for_test(absent.module.get());
        if (!require(install_xinput(0), "an absent ordinal must permit initial exact authorization"))
            return false;
        auto layer = install_layer(absent, 0, LayerMode::Forward);
        if (!require(layer && !install_xinput(0), "a disconnected foreign primary must refuse observed authorization"))
            return false;
        const std::string_view warning{s_last_warning.data(), s_last_warning_length};
        const auto absent_start = warning.find("XInputGetStateEx:");
        if (!require(absent_start != std::string_view::npos, "the absent member must have its own diagnostic"))
            return false;
        const auto absent_fields = warning.substr(absent_start);
        if (!require(
                absent_fields.contains("call=absent, authentication=unmeasured") && !absent_fields.contains("result="),
                "an absent ordinal must report no invocation, result, or authentication measurement"
            ))
            return false;
        if (!require(layer->disable().has_value(), "the absent-ordinal handler must hand back"))
            return false;
        layer.reset();
        s_layer_original[0].store(nullptr);
        uninstall();
        return require(
            !xinput_installed() && xinput_module_refs_held() == 0 && original_bytes == snapshot(absent.targets[0]),
            "absent-ordinal teardown must restore bytes and release every provider reference"
        );
    }

    int run_scope_diagnostics()
    {
        using namespace DetourModKit::detail;
        Provider provider;
        const PairLogObserver observer;
        if (!require(provider.prepare(), "the scope fixture must load"))
            return 100;
        set_xinput_module_override_for_test(provider.module.get());
        if (!require(install_xinput(0), "the scope pair must install"))
            return 101;
        auto primary_layer_hook = install_layer(provider, 0, LayerMode::Forward);
        auto ex_layer_hook = install_layer(provider, 1, LayerMode::Forward);
        if (!require(primary_layer_hook && ex_layer_hook && install_xinput(0), "both scope forwarders must authorize"))
            return 102;
        set_xinput_route_probe_failures_for_test(false, true, false);
        const bool admission_refused = !install_xinput(0) && warning_contains("pair: admission=failed") &&
                                       warning_contains("call=uninvoked, authentication=unmeasured");
        set_xinput_route_probe_failures_for_test(false, false, false);
        if (!require(
                admission_refused && install_xinput(0),
                "admission must identify uninvoked members without results"
            ))
            return 103;
        close_xinput_route_probes();
        if (!require(
                release_xinput_route_probe_if_idle(),
                "the idle receipt slot must return before reservation refusal"
            ))
            return 103;
        set_xinput_route_probe_failures_for_test(true, false, false);
        const bool reservation_refused = !install_xinput(0) &&
                                         warning_contains("pair: admission=failed, raw_scope=unmeasured") &&
                                         warning_contains("call=uninvoked, authentication=unmeasured");
        set_xinput_route_probe_failures_for_test(false, false, false);
        if (!require(reservation_refused && install_xinput(0), "reservation failure must fabricate no provider result"))
            return 103;
        if (!require(
                set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::EntryStore),
                "raw entry refusal must arm"
            ))
            return 103;
        const bool raw_entry_refused = !install_xinput(0) && warning_contains("raw_scope=failed") &&
                                       warning_contains("probe=passed, call=uninvoked, authentication=unmeasured");
        if (!require(
                set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::None) && raw_entry_refused &&
                    install_xinput(0),
                "raw entry failure must differ from receipt probe admission failure"
            ))
            return 103;
        if (!require(
                set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::Restore),
                "raw restore refusal must arm"
            ))
            return 104;
        const bool restore_refused = !install_xinput(0) && warning_contains("raw_restore=failed") &&
                                     warning_contains("call=returned result=0, authentication=matched");
        if (!require(
                set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::None) &&
                    TlsSetValue(xinput_raw_scope_index_for_test(), nullptr) != FALSE && restore_refused &&
                    install_xinput(0),
                "raw restoration failure must stay a pair cause despite authenticated successful returns"
            ))
            return 105;

        s_probe_thread_id = GetCurrentThreadId();
        s_parked.store(false);
        s_release_park.store(false);
        s_layer_mode[0].store(LayerMode::Park);
        bool probe_result = true;
        std::thread probe([&probe_result]() -> void { probe_result = install_xinput(0); });
        const bool parked = wait_for([]() -> bool { return s_parked.load(std::memory_order_acquire); });
        const bool handed_back = parked && ex_layer_hook->disable().has_value();
        s_release_park.store(true, std::memory_order_release);
        probe.join();
        if (!require(
                parked && handed_back && !probe_result && warning_contains("snapshot=failed") &&
                    warning_contains("call=returned result=0, authentication=matched"),
                "a concurrent hand-back must report a changed pair snapshot instead of a member failure"
            ))
            return 106;
        s_layer_mode[0].store(LayerMode::Forward);
        ex_layer_hook.reset();
        s_layer_original[1].store(nullptr);
        if (!require(install_xinput(0), "fresh evidence must recover after the snapshot transition"))
            return 107;

        if (!require(
                set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::ConsumeOriginalStore),
                "the context fault must arm"
            ))
            return 108;
        XINPUT_STATE state{};
        const DWORD result = provider.routes[0](0, &state);
        if (!require(
                set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure::None) && result == ERROR_SUCCESS &&
                    !xinput_consume_context_healthy() && !install_xinput(0) && warning_contains("context=failed") &&
                    warning_contains("call=returned result=0, authentication=matched"),
                "poisoned context must report a pair failure even when both providers return success"
            ))
            return 109;
        if (!require(
                s_pair_warnings.load() == 6 && s_pair_recoveries.load() == 5 && s_warning_reentry_succeeded.load(),
                "scope failures must each own one episode and permit observer reentry"
            ))
            return 110;
        if (!require(primary_layer_hook->disable().has_value(), "the scope handler must hand back"))
            return 111;
        primary_layer_hook.reset();
        s_layer_original[0].store(nullptr);
        uninstall();
        if (!require(
                !xinput_installed() && xinput_module_refs_held() == 0 && check_provider(provider, 0),
                "scope teardown must restore raw exports and release provider references"
            ))
            return 112;
        if (!verify_absent_member_diagnostic())
            return 112;
        set_xinput_module_override_for_test(nullptr);
        return 0;
    }

    int run_parked_probe(bool replace_owner)
    {
        using namespace DetourModKit::detail;
        Provider provider;
        const PairLogObserver observer;
        if (!require(provider.prepare(), "the parked-probe fixture must load"))
            return 40;
        set_xinput_module_override_for_test(provider.module.get());
        s_probe_thread_id = GetCurrentThreadId();
        if (!require(install_xinput(0), "the parked-probe base pair must install"))
            return 41;
        if (!require(
                publish_gamepad_suppress(SUPPRESS_BITS, STANDALONE_INTERCEPT_OWNER),
                "the parked-probe cycle must start with a live mask"
            ))
            return 41;
        set_xinput_detour_body_seam(&note_primary_entry);
        s_primary_entries.store(0, std::memory_order_relaxed);
        const XInputGetStateFn saved_primary = xinput_trampoline();
        auto layer = install_layer(provider, 0, LayerMode::Park);
        if (!require(layer.has_value(), "the upstream handler must arm"))
            return 42;
        if (replace_owner)
        {
            s_layer_mode[0].store(LayerMode::Forward);
            if (!require(
                    install_xinput(0) && reported_loss(0, LayerMode::Bypass),
                    "a stale recovery probe must start from a reported episode"
                ))
                return 42;
            s_layer_mode[0].store(LayerMode::Park);
            s_primary_entries.store(0, std::memory_order_relaxed);
        }
        const std::array<ByteWindow, 2> parked_bytes{snapshot(provider.targets[0]), snapshot(provider.targets[1])};
        s_parked.store(false, std::memory_order_relaxed);
        s_release_park.store(false, std::memory_order_relaxed);
        s_parked_call_raw_success.store(false, std::memory_order_relaxed);
        std::atomic<bool> probe_result{true};
        std::thread probe(
            [&probe_result]() -> void { probe_result.store(install_xinput(0), std::memory_order_release); }
        );
        if (!wait_for([]() -> bool { return s_parked.load(std::memory_order_acquire); }))
        {
            s_release_park.store(true, std::memory_order_release);
            probe.join();
            return 43;
        }
        const auto begin = GetTickCount64();
        uninstall();
        const auto elapsed = GetTickCount64() - begin;
        const std::uint64_t successor = next_intercept_owner();
        const bool successor_adopted = !replace_owner || adopt_owner_for_test(successor);
        const bool successor_write = !replace_owner || publish_gamepad_suppress(XINPUT_GAMEPAD_B, successor);
        const bool successor_degraded = xinput_pair_degraded_for_test();
        XINPUT_STATE saved_primary_state{};
        const bool safely_retained =
            !xinput_installed() && xinput_module_refs_held() == 2 && xinput_trampoline() == nullptr && elapsed < 3000 &&
            s_primary_entries.load(std::memory_order_relaxed) == 0 &&
            saved_primary(0, &saved_primary_state) == ERROR_SUCCESS &&
            fields_match(saved_primary_state, provider.raw[0][0], 0) &&
            parked_bytes[0] == snapshot(provider.targets[0]) && parked_bytes[1] == snapshot(provider.targets[1]);
        s_release_park.store(true, std::memory_order_release);
        probe.join();
        if (!require(
                safely_retained && successor_adopted && successor_write &&
                    !probe_result.load(std::memory_order_acquire) && !xinput_installed() &&
                    s_parked_call_raw_success.load(std::memory_order_acquire) &&
                    s_pair_warnings.load() == (replace_owner ? 1u : 0u) && s_pair_recoveries.load() == 0 &&
                    xinput_pair_degraded_for_test() == successor_degraded,
                "a pre-admission probe must retain its chain and cannot publish a stale owner receipt"
            ))
            return 44;
        if (replace_owner &&
            !require(
                !publish_gamepad_suppress(SUPPRESS_BITS, STANDALONE_INTERCEPT_OWNER) && intercept_owned_by(successor),
                "the stale probe must preserve successor authorization"
            ))
            return 45;
        if (!require(layer->disable().has_value(), "the parked handler must hand back after its caller returns"))
            return 46;
        layer.reset();
        s_layer_original[0].store(nullptr, std::memory_order_release);
        if (!require(
                install_xinput(0, replace_owner ? successor : STANDALONE_INTERCEPT_OWNER) &&
                    s_pair_recoveries.load() == 0,
                "the retained pair must recover for the current owner"
            ))
            return 47;
        if (!require(
                check_provider(provider, replace_owner ? XINPUT_GAMEPAD_B : 0),
                "the stale receipt must preserve the successor's original mask"
            ))
            return 48;
        set_xinput_detour_body_seam(nullptr);
        uninstall(replace_owner ? successor : STANDALONE_INTERCEPT_OWNER);
        if (!require(check_provider(provider, 0), "the retained provider calls must stay raw after teardown"))
            return 49;
        set_xinput_module_override_for_test(nullptr);
        std::printf(
            "PASS: %s retained both chains after %llu ms of bounded teardown\n",
            replace_owner ? "stale-owner probe" : "pre-admission probe",
            elapsed
        );
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 1;
    const std::string_view scenario{argv[1]};
    if (scenario == "conditional-primary")
        return run_conditional_case(false);
    if (scenario == "conditional-ex")
        return run_conditional_case(true);
    if (scenario == "forwarding-primary" || scenario == "forwarding-ex" || scenario == "forwarding-both" ||
        scenario == "nonforwarding-primary" || scenario == "nonforwarding-ex")
        return run_layered_binding_case(scenario);
    if (scenario == "ten-copies-forward" || scenario == "ten-copies-reverse")
        return run_ten_copies(scenario == "ten-copies-reverse");
    if (scenario == "two-copies-first-frame-forward" || scenario == "two-copies-first-frame-reverse")
        return run_two_copy_first_frame(scenario == "two-copies-first-frame-reverse");
    if (scenario == "two-copies-transforming-forwarder")
        return run_transforming_forwarder();
    if (scenario == "probe-before-admission" || scenario == "epoch-race")
        return run_parked_probe(scenario == "epoch-race");
    if (scenario == "diagnostics-scope")
        return run_scope_diagnostics();
    if (scenario == "disconnected-startup")
        return run_layered_binding_case(scenario);
    if (scenario == "observed-reconnect" || scenario == "diagnostics-primary" || scenario == "diagnostics-ex" ||
        scenario == "exact-recovery")
        return run_measured_diagnostics(scenario);
    if (scenario == "route-diagnostics")
        return run_route_diagnostics();
    std::fputs("unknown conditional XInput scenario\n", stderr);
    return 1;
}
