/**
 * @file input_poller.cpp
 * @brief Implementation of the internal input poll engine (input_poller.hpp).
 *
 * Drives the public input::Input facade. A background poll thread reads keyboard, mouse, gamepad, and mouse-wheel
 * state. It detects press and hold edges under strict modifier rules and feeds the opt-in interception layer.
 */

#include "input_poller.hpp"
#include "drain_backoff.hpp"
#include "input_delivery_scope.hpp"
#include "input_intercept.hpp"
#include "input_key_cache.hpp"
#include "lifecycle_context.hpp"
#include "platform.hpp"

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/logger.hpp"

#include <windows.h>
#include <xinput.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <shared_mutex>
#include <system_error>
#include <thread>
#include <type_traits>
#include <unordered_set>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            /**
             * @brief Checks whether a single InputCode is currently pressed.
             * @param wheel_pulse Per-cycle wheel pulse mask (bit 0 = WheelUp .. bit 3 = WheelRight), latched once
             *        per cycle so repeated reads within a cycle stay consistent.
             */
            bool is_code_pressed(const InputCode &code, KeyStateCache &key_cache, const XINPUT_STATE &gamepad_state,
                                 bool gamepad_connected, int trigger_threshold, int stick_threshold,
                                 uint8_t wheel_pulse) noexcept
            {
                switch (code.source)
                {
                case InputSource::Keyboard:
                case InputSource::Mouse:
                    // The per-cycle cache makes a VK referenced by many bindings cost one GetAsyncKeyState call per
                    // cycle and gives the whole cycle one coherent sample.
                    return code.code != 0 && key_cache.pressed(code.code,
                                                               [](int vk) noexcept
                                                               {
#ifdef DMK_ENABLE_TEST_SEAMS
                                                                   if (g_input_key_state_probe)
                                                                   {
                                                                       return g_input_key_state_probe(vk);
                                                                   }
#endif
                                                                   return (GetAsyncKeyState(vk) & 0x8000) != 0;
                                                               });
                case InputSource::MouseWheel:
                {
                    // The wheel has no held state. The poll loop latches each notch into wheel_pulse. WheelCode values
                    // are 1-based and dense, so the direction index is code - WheelCode::Up.
                    const int dir = code.code - WheelCode::Up;
                    if (dir < 0 || dir > 3)
                    {
                        return false;
                    }
                    return (wheel_pulse & (1u << dir)) != 0;
                }
                case InputSource::Gamepad:
                {
                    if (!gamepad_connected)
                    {
                        return false;
                    }
                    // Fast path: digital button bitmask (all codes below synthetic range)
                    if (code.code < GamepadCode::LeftTrigger)
                    {
                        return (gamepad_state.Gamepad.wButtons & static_cast<WORD>(code.code)) != 0;
                    }
                    // Synthetic analog codes
                    switch (code.code)
                    {
                    case GamepadCode::LeftTrigger:
                        return gamepad_state.Gamepad.bLeftTrigger > trigger_threshold;
                    case GamepadCode::RightTrigger:
                        return gamepad_state.Gamepad.bRightTrigger > trigger_threshold;
                    case GamepadCode::LeftStickUp:
                        return gamepad_state.Gamepad.sThumbLY > stick_threshold;
                    case GamepadCode::LeftStickDown:
                        return gamepad_state.Gamepad.sThumbLY < -stick_threshold;
                    case GamepadCode::LeftStickLeft:
                        return gamepad_state.Gamepad.sThumbLX < -stick_threshold;
                    case GamepadCode::LeftStickRight:
                        return gamepad_state.Gamepad.sThumbLX > stick_threshold;
                    case GamepadCode::RightStickUp:
                        return gamepad_state.Gamepad.sThumbRY > stick_threshold;
                    case GamepadCode::RightStickDown:
                        return gamepad_state.Gamepad.sThumbRY < -stick_threshold;
                    case GamepadCode::RightStickLeft:
                        return gamepad_state.Gamepad.sThumbRX < -stick_threshold;
                    case GamepadCode::RightStickRight:
                        return gamepad_state.Gamepad.sThumbRX > stick_threshold;
                    default:
                        return false;
                    }
                }
                }
                return false;
            }

            /**
             * @brief Checks if a held input satisfies a required modifier.
             * @details Returns true when the codes match exactly. It also returns true for keyboard modifiers in the
             *          same family. For example, LShift satisfies generic Shift, and generic Shift satisfies LShift.
             */
            bool modifier_satisfies(const InputCode &required, const InputCode &held) noexcept
            {
                if (required == held)
                {
                    return true;
                }
                if (required.source != InputSource::Keyboard || held.source != InputSource::Keyboard)
                {
                    return false;
                }
                // Modifier family groups: {generic, left, right}
                constexpr int families[][3] = {
                    {0x11, 0xA2, 0xA3}, // Ctrl, LCtrl, RCtrl
                    {0x10, 0xA0, 0xA1}, // Shift, LShift, RShift
                    {0x12, 0xA4, 0xA5}, // Alt, LAlt, RAlt
                };
                for (const auto &family : families)
                {
                    bool req_in = false;
                    bool held_in = false;
                    for (int vk : family)
                    {
                        if (required.code == vk)
                        {
                            req_in = true;
                        }
                        if (held.code == vk)
                        {
                            held_in = true;
                        }
                    }
                    if (req_in && held_in)
                    {
                        return true;
                    }
                }
                return false;
            }

            /**
             * @brief Reports whether any binding uses a gamepad InputCode.
             * @param bindings Bindings to inspect.
             * @return true when at least one binding contains a gamepad InputCode.
             */
            bool scan_for_gamepad_bindings(const std::vector<InputBinding> &bindings) noexcept
            {
                for (const auto &binding : bindings)
                {
                    for (const auto &key : binding.keys)
                    {
                        if (key.source == InputSource::Gamepad)
                        {
                            return true;
                        }
                    }
                    for (const auto &mod : binding.modifiers)
                    {
                        if (mod.source == InputSource::Gamepad)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            /**
             * @brief Reports whether any binding uses a mouse-wheel trigger.
             * @details Wheel codes only appear as trigger keys (never modifiers), so modifiers are not scanned.
             */
            bool scan_for_wheel_bindings(const std::vector<InputBinding> &bindings) noexcept
            {
                for (const auto &binding : bindings)
                {
                    for (const auto &key : binding.keys)
                    {
                        if (key.source == InputSource::MouseWheel)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            /**
             * @brief Reports whether any consume binding carries a suppressible gamepad button (gates the XInput hook).
             * @details Only digital buttons gate it: the detour masks wButtons, so analog codes can never be
             *          cleared. Analog codes do not justify hook installation because the hook cannot mask them.
             */
            bool scan_for_consume_gamepad_bindings(const std::vector<InputBinding> &bindings) noexcept
            {
                for (const auto &binding : bindings)
                {
                    if (!binding.consume)
                    {
                        continue;
                    }
                    for (const auto &key : binding.keys)
                    {
                        if (key.source == InputSource::Gamepad && key.code > 0 && key.code < GamepadCode::LeftTrigger)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            /**
             * @brief Builds the detour-evaluable consume rule list from the current bindings.
             * @details Rules exist only when every known modifier is a digital gamepad button available in wButtons.
             *          Otherwise, the detour cannot reproduce the poll loop's strict-match decision. The whole list
             *          is dropped. The reactive mask still covers the held-modifier case. A rule
             *          carries the chord's modifier bits, its digital trigger bits to clear, and a forbidden mask
             *          of every other known modifier bit. Exact-duplicate triples are emitted once, so the rule
             *          budget is a budget of distinct chord shapes.
             */
            std::vector<GamepadConsumeRule> build_gamepad_consume_rules(const std::vector<InputBinding> &bindings,
                                                                        const std::vector<InputCode> &known_modifiers)
            {
                const auto is_digital_gamepad = [](const InputCode &code) noexcept
                {
                    return code.source == InputSource::Gamepad && code.code > 0 && code.code < GamepadCode::LeftTrigger;
                };

                uint16_t known_mod_mask = 0;
                for (const auto &mod : known_modifiers)
                {
                    if (!is_digital_gamepad(mod))
                    {
                        return {};
                    }
                    known_mod_mask = static_cast<uint16_t>(known_mod_mask | static_cast<uint16_t>(mod.code));
                }

                std::vector<GamepadConsumeRule> rules;
                for (const auto &binding : bindings)
                {
                    if (!binding.consume)
                    {
                        continue;
                    }
                    uint16_t trigger_mask = 0;
                    for (const auto &key : binding.keys)
                    {
                        if (is_digital_gamepad(key))
                        {
                            trigger_mask = static_cast<uint16_t>(trigger_mask | static_cast<uint16_t>(key.code));
                        }
                    }
                    if (trigger_mask == 0)
                    {
                        // No digital gamepad trigger exists to clear. The detour has nothing to mask here.
                        continue;
                    }
                    // Every modifier is digital here: the gate above returned an empty list otherwise.
                    uint16_t modifier_mask = 0;
                    for (const auto &mod : binding.modifiers)
                    {
                        modifier_mask = static_cast<uint16_t>(modifier_mask | static_cast<uint16_t>(mod.code));
                    }
                    const uint16_t forbidden_mask =
                        static_cast<uint16_t>(known_mod_mask & static_cast<uint16_t>(~modifier_mask));
                    const auto duplicate = std::find_if(rules.begin(), rules.end(),
                                                        [&](const GamepadConsumeRule &rule) noexcept
                                                        {
                                                            return rule.modifier_mask == modifier_mask &&
                                                                   rule.forbidden_mask == forbidden_mask &&
                                                                   rule.trigger_mask == trigger_mask;
                                                        });
                    if (duplicate == rules.end())
                    {
                        rules.push_back(GamepadConsumeRule{modifier_mask, forbidden_mask, trigger_mask});
                    }
                }
                return rules;
            }

            // Release grace for gamepad consume-until-release: long enough to absorb the
            // modifier-released-before-trigger window without noticeable delay to a deliberate tap.
            constexpr uint64_t GAMEPAD_SUPPRESS_GRACE_MS = 80;

            // Process-wide monotonic source for BindingToken generations, so a token minted by one poller can never
            // alias a different poller's state. The source starts at 1. The value 0 remains reserved for an invalid
            // token.
            std::atomic<std::uint64_t> s_next_binding_generation{1};

            /// Draws a unique binding generation with a relaxed operation that does not publish state.
            std::uint64_t next_binding_generation() noexcept
            {
                return s_next_binding_generation.fetch_add(1, std::memory_order_relaxed);
            }

            /// Ensures @p binding carries a lifecycle control block. Allocates only for directly seeded entries.
            void ensure_lifecycle(InputBinding &binding)
            {
                if (!binding.lifecycle)
                {
                    binding.lifecycle = make_binding_lifecycle();
                }
            }

            struct BindingRundown
            {
                std::shared_ptr<BindingLifecycle> lifecycle;
                std::uint64_t generation{0};
            };

            // One action per release. Parallel containers can diverge in length when only one of the two copies
            // succeeds, which leaves dispatch with a name that was never staged. A single object cannot produce this
            // split.
            struct HoldRelease
            {
                std::function<void(bool)> callback;
                std::string name;
            };

            void add_rundown(std::vector<BindingRundown> &rundowns, const std::shared_ptr<BindingLifecycle> &lifecycle)
            {
                if (!lifecycle)
                {
                    return;
                }
                const auto duplicate =
                    std::find_if(rundowns.begin(), rundowns.end(), [&lifecycle](const BindingRundown &rundown)
                                 { return rundown.lifecycle == lifecycle; });
                if (duplicate == rundowns.end())
                {
                    rundowns.push_back({lifecycle, 0});
                }
            }

            void drain_rundowns(const std::vector<BindingRundown> &rundowns) noexcept
            {
                if (current_thread_in_delivery())
                {
                    return;
                }
                for (const auto &rundown : rundowns)
                {
                    // A tombstoned registration admits nothing further, so wait for every in-flight callback
                    // regardless of parity slot. An advanced live registration still admits new-generation
                    // callbacks, so it drains only the retired slot.
                    DrainBackoff backoff;
                    if (rundown.lifecycle->tombstoned())
                    {
                        while (rundown.lifecycle->in_flight_total() != 0)
                        {
                            backoff.pause();
                        }
                    }
                    else
                    {
                        while (rundown.lifecycle->in_flight(rundown.generation) != 0)
                        {
                            backoff.pause();
                        }
                    }
                }
            }
        } // anonymous namespace

#ifdef DMK_ENABLE_TEST_SEAMS
        std::function<bool(int)> g_input_key_state_probe;
        std::function<void(std::size_t)> g_input_post_stage_probe;
        std::function<void()> g_input_pre_dispatch_probe;
        void (*g_input_join_fail_seam)() = nullptr;
#endif

        std::shared_ptr<BindingLifecycle> make_binding_lifecycle()
        {
            static std::atomic<bool> s_tls_warned{false};
            if (!reserve_delivery_scope_tls() && !s_tls_warned.exchange(true, std::memory_order_relaxed))
            {
                (void)log().try_log(LogLevel::Error,
                                    "InputPoller: no TLS slot is available for the input delivery marker; input "
                                    "callbacks are refused rather than delivered without per-thread identity.");
            }
            return std::make_shared<BindingLifecycle>(next_binding_generation());
        }

        static_assert(std::is_nothrow_move_assignable_v<InputBinding>,
                      "Input reshape commits rely on noexcept InputBinding move assignment");
        static_assert(std::is_nothrow_move_constructible_v<InputBinding>,
                      "Input reshape commits rely on noexcept InputBinding move construction");

        InputPoller::InputPoller(std::vector<InputBinding> bindings, std::chrono::milliseconds poll_interval,
                                 bool require_focus, int gamepad_index, int trigger_threshold, int stick_threshold)
            : m_bindings(std::move(bindings)),
              m_poll_interval(std::clamp(poll_interval, input::MIN_POLL_INTERVAL, input::MAX_POLL_INTERVAL)),
              m_require_focus(require_focus),
              m_active_states(std::make_unique<std::atomic<uint8_t>[]>(m_bindings.size())),
              m_gamepad_index(std::clamp(gamepad_index, 0, 3)),
              m_trigger_threshold(std::clamp(trigger_threshold, 0, 255)),
              m_stick_threshold(std::clamp(stick_threshold, 0, 32767)), m_intercept_owner(next_intercept_owner())
        {
            m_name_index.reserve(m_bindings.size());
            // Stamp a lifecycle on any binding seeded without one, so the poll loop's generation-safety check has
            // an identity to compare against.
            for (auto &binding : m_bindings)
            {
                ensure_lifecycle(binding);
            }
            recompute_modifier_caches_locked();
        }

        void InputPoller::recompute_modifier_caches_locked(CacheFailPolicy policy) noexcept
        {
            // Snapshot wheel ownership before this reshape. The installed detour continues to latch notches across an
            // unbind -> rebind while the poll loop skips the drain. A stale backlog accumulates in the unowned window.
            // The no-wheel -> wheel transition below must discard it.
            const bool had_wheel_bindings = m_has_wheel_bindings.load(std::memory_order_relaxed);

            // Advance the generation before the rebuild. Even if the rebuild fails into the catch, every live
            // BindingToken becomes invalid and fails closed until another acquisition.
            m_binding_generation = next_binding_generation();

            // Rebuild into locals and commit with noexcept moves only after every allocation succeeds. This helper is
            // noexcept and reachable from loader-lock teardown.
            try
            {
                decltype(m_name_index) name_index;
                std::unordered_set<InputCode, InputCodeHash> modifier_set;
                for (size_t i = 0; i < m_bindings.size(); ++i)
                {
                    if (!m_bindings[i].name.empty())
                    {
                        name_index[m_bindings[i].name].push_back(i);
                    }
                    for (const auto &mod : m_bindings[i].modifiers)
                    {
                        modifier_set.insert(mod);
                    }
                }
                std::vector<InputCode> known_modifiers(modifier_set.begin(), modifier_set.end());

                // Built from the same bindings and modifier set as the reactive path so the two never disagree.
                std::vector<GamepadConsumeRule> consume_rules =
                    build_gamepad_consume_rules(m_bindings, known_modifiers);

                // Commit. Container move assignment does not allocate, so the function cannot fail after this point.
                m_consume_rules = std::move(consume_rules);
                m_name_index = std::move(name_index);
                m_known_modifiers = std::move(known_modifiers);
                m_has_gamepad_bindings.store(scan_for_gamepad_bindings(m_bindings), std::memory_order_relaxed);
                const bool now_has_wheel_bindings = scan_for_wheel_bindings(m_bindings);
                m_has_consume_gamepad_bindings.store(scan_for_consume_gamepad_bindings(m_bindings),
                                                     std::memory_order_relaxed);

                // Offer the detour-side consume rule list. A poller that does not hold the layer keeps the rules
                // cached and does not overwrite the owner's list.
                publish_consume_rules_locked();

                // On the no-wheel -> wheel transition, discard whatever the detour latched while no binding owned
                // the wheel. The published flag stays false until after this drain. Otherwise, the poll thread can
                // consume the stale backlog before this thread clears it. A non-owner drains nothing. That backlog
                // belongs to the owner's window.
                if (!had_wheel_bindings && now_has_wheel_bindings)
                {
                    (void)take_wheel_counts(m_intercept_owner);
                }
                // Release pairs with the poll cycle's acquire snapshot and publishes the drain before consumption.
                m_has_wheel_bindings.store(now_has_wheel_bindings, std::memory_order_release);
            }
            catch (...)
            {
                if (policy == CacheFailPolicy::Retain)
                {
                    // Keep the lookup caches (the caller changed a flag, not the binding set) but disarm the
                    // suppression. A retained rule list has no independent expiry and masks a revoked chord for the
                    // rest of the process.
                    m_has_consume_gamepad_bindings.store(false, std::memory_order_relaxed);
                    m_consume_rules.clear();
                    publish_consume_rules_locked();
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: out of memory rebuilding modifier caches; name lookup is "
                                        "retained and gamepad consume suppression is disarmed until the next "
                                        "successful rebuild");
                    return;
                }

                // Keep every derived cache conservative and index-safe rather than leave a stale name map whose old
                // indices can address past the new binding array.
                m_name_index.clear();
                m_known_modifiers.clear();
                m_has_gamepad_bindings.store(false, std::memory_order_relaxed);
                m_has_wheel_bindings.store(false, std::memory_order_relaxed);
                m_has_consume_gamepad_bindings.store(false, std::memory_order_relaxed);
                m_consume_rules.clear();
                publish_consume_rules_locked();
                (void)log().try_log(LogLevel::Error,
                                    "InputPoller: out of memory rebuilding modifier caches; "
                                    "name lookup and input interception disabled until the next successful rebuild");
            }
        }

        void InputPoller::publish_consume_rules_locked() noexcept
        {
            const ConsumePublish result =
                publish_gamepad_consume_rules(m_consume_rules.data(), m_consume_rules.size(), m_intercept_owner);
            if (!result.authorized)
            {
                // Not this poller's layer: report zero occupancy and keep the rules cached for the retry.
                m_consume_rules_unpublished.store(true, std::memory_order_release);
                record_consume_capacity(0, 0);
                return;
            }
            m_consume_rules_unpublished.store(false, std::memory_order_release);
            record_consume_capacity(result.published, m_consume_rules.size() - result.published);
        }

#ifdef DMK_ENABLE_TEST_SEAMS
        void InputPoller::publish_consume_rules_for_test() noexcept
        {
            std::unique_lock lock(m_bindings_rw_mutex);
            publish_consume_rules_locked();
        }
#endif

        void InputPoller::record_consume_capacity(std::size_t active, std::size_t rejected) noexcept
        {
            m_consume_rules_total.store(active + rejected, std::memory_order_relaxed);
            if (rejected == 0)
            {
                return;
            }
            // Latch per engine. An unlatched log repeats the same condition on every publish. A process-wide latch
            // silences a later engine's overflow.
            if (m_consume_bound_reported.exchange(true, std::memory_order_relaxed))
            {
                return;
            }
            (void)log().try_log(LogLevel::Warning,
                                "InputPoller: {} of {} gamepad consume chords exceed the interception table; "
                                "they keep the reactive mask but lose same-frame suppression",
                                rejected, active + rejected);
        }

        input::ConsumeCapacity InputPoller::consume_capacity() const noexcept
        {
            const std::size_t total = m_consume_rules_total.load(std::memory_order_relaxed);
            const std::size_t active = std::min(total, MAX_GAMEPAD_CONSUME_RULES);
            return input::ConsumeCapacity{MAX_GAMEPAD_CONSUME_RULES, active, total - active};
        }

        InputPoller::~InputPoller() noexcept
        {
            shutdown();
        }

        void InputPoller::start()
        {
            if (m_poll_thread.joinable())
            {
                log().debug("InputPoller: start() called while already running; no-op.");
                return;
            }

            // Acquire before poll-thread creation because execution can start immediately. Its module reference must
            // already be part of the count.
            const HMODULE self_ref = acquire_module_ref();
            if (self_ref == nullptr)
            {
                throw std::system_error(static_cast<int>(GetLastError()), std::system_category(),
                                        "InputPoller: acquire_module_ref failed");
            }

            m_running.store(true, std::memory_order_release);
            try
            {
                m_poll_thread = std::jthread([this](std::stop_token token) { poll_loop(std::move(token)); });
            }
            catch (...)
            {
                m_running.store(false, std::memory_order_release);
                release_module_ref(self_ref);
                throw;
            }
            m_self_ref = self_ref;
        }

        bool InputPoller::is_running() const noexcept
        {
            return m_running.load(std::memory_order_acquire);
        }

        size_t InputPoller::binding_count() const noexcept
        {
            std::shared_lock lock(m_bindings_rw_mutex);
            return m_bindings.size();
        }

        bool InputPoller::has_bindings_by_name(std::string_view name) const noexcept
        {
            std::shared_lock lock(m_bindings_rw_mutex);
            return m_name_index.contains(name);
        }

        std::chrono::milliseconds InputPoller::poll_interval() const noexcept
        {
            return m_poll_interval;
        }

        int InputPoller::gamepad_index() const noexcept
        {
            return m_gamepad_index;
        }

        bool InputPoller::is_binding_active(size_t index) const noexcept
        {
            // The shared lock keeps the index and array consistent across a reshape. The unique_ptr<atomic[]>
            // ownership swap that needs synchronization, not the cheap relaxed element load.
            std::shared_lock lock(m_bindings_rw_mutex);
            if (index >= m_bindings.size())
            {
                return false;
            }
            return m_active_states[index].load(std::memory_order_relaxed) != 0;
        }

        bool InputPoller::is_binding_active(std::string_view name) const noexcept
        {
            std::shared_lock lock(m_bindings_rw_mutex);
            const auto it = m_name_index.find(name);
            if (it != m_name_index.end())
            {
                for (const size_t idx : it->second)
                {
                    // The shared lock holds idx in bounds. The explicit check is defense in depth against a future
                    // reshape that repopulates m_name_index without a corresponding m_active_states resize.
                    if (idx < m_bindings.size() && m_active_states[idx].load(std::memory_order_relaxed) != 0)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        input::BindingToken InputPoller::acquire_binding_token(std::string_view name) const noexcept
        {
            input::BindingToken token;
            try
            {
                std::shared_lock lock(m_bindings_rw_mutex);
                const auto it = m_name_index.find(name);
                if (it == m_name_index.end())
                {
                    // Unknown name: leave the token invalid (generation 0).
                    return token;
                }
                // Copy the indices first because only this step can throw. Then stamp the generation. An allocation
                // failure leaves the token invalid instead of valid but empty.
                token.m_indices = it->second;
                token.m_generation = m_binding_generation;
            }
            catch (...)
            {
                // Out of memory: return an invalid token so the consumer falls back to the name-based query.
                return input::BindingToken{};
            }
            return token;
        }

        bool InputPoller::is_binding_active(const input::BindingToken &token) const noexcept
        {
            if (!token.valid())
            {
                return false;
            }
            std::shared_lock lock(m_bindings_rw_mutex);
            // A generation mismatch means the cached indices can refer to different bindings. Fail closed.
            if (token.m_generation != m_binding_generation)
            {
                return false;
            }
            for (const size_t idx : token.m_indices)
            {
                // The generation match proves idx in bounds. The explicit check is defense in depth against a
                // future reshape path that forgets to advance the generation.
                if (idx < m_bindings.size() && m_active_states[idx].load(std::memory_order_relaxed) != 0)
                {
                    return true;
                }
            }
            return false;
        }

        bool InputPoller::binding_token_current(const input::BindingToken &token) const noexcept
        {
            if (!token.valid())
            {
                return false;
            }
            std::shared_lock lock(m_bindings_rw_mutex);
            return token.m_generation == m_binding_generation;
        }

        void InputPoller::set_require_focus(bool require_focus) noexcept
        {
            m_require_focus.store(require_focus, std::memory_order_relaxed);
        }

        void InputPoller::set_consume(std::string_view name, bool consume) noexcept
        {
            std::unique_lock lock(m_bindings_rw_mutex);
            const auto it = m_name_index.find(name);
            if (it == m_name_index.end())
            {
                return;
            }
            for (const size_t idx : it->second)
            {
                m_bindings[idx].consume = consume;
            }
            // Refresh the interception gates so the poll loop installs or skips the
            // XInput / window-procedure hooks on its next cycle.
            recompute_modifier_caches_locked(CacheFailPolicy::Retain);
        }

        void InputPoller::set_consume_by_owner(std::uint64_t owner, bool consume) noexcept
        {
            // The value 0 is the "no owner" sentinel. Skip the scan so an unstamped call cannot clear all owner-0
            // bindings.
            if (owner == 0)
            {
                return;
            }
            std::unique_lock lock(m_bindings_rw_mutex);
            bool changed = false;
            for (auto &binding : m_bindings)
            {
                if (binding.consume_owner == owner && binding.consume != consume)
                {
                    binding.consume = consume;
                    changed = true;
                }
            }
            // Rebuild only on a real transition. A redundant rebuild advances the generation and makes every live
            // BindingToken stale despite no state change.
            if (changed)
            {
                recompute_modifier_caches_locked(CacheFailPolicy::Retain);
            }
        }

        void InputPoller::shutdown() noexcept
        {
            if (!m_poll_thread.joinable())
            {
                // Release the precommitted keepalive so an unstarted poller does not remain for the process lifetime.
                // Preserve it after a detach because that thread can still read these members.
                if (!m_requires_abandonment.load(std::memory_order_acquire))
                {
                    m_owner_keepalive.reset();
                }
                return;
            }

            m_poll_thread.request_stop();
            m_cv.notify_all();

            if (!blocking_teardown_permitted())
            {
                // No authorization exists to block. A join can deadlock the loader, so detach the thread and leak its
                // module reference. The detached thread still executes, so shared binding state and hold-release
                // callbacks must not be touched here (mirrors clear_bindings(invoke_callbacks=false)).
                m_requires_abandonment.store(true, std::memory_order_release);
                try
                {
                    m_poll_thread.detach();
                }
                catch (...)
                {
                    // The abandonment flag pins the keepalive, so the poller (and its jthread member) is never
                    // destroyed and ~jthread's loader-lock join is never reached.
                }
                DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
                m_running.store(false, std::memory_order_release);
                return;
            }

            if (m_poll_thread.get_id() == std::this_thread::get_id())
            {
                // The poll thread is its own teardown thread after a callback reaches this path. A self-join raises,
                // and every later step is unsafe while this thread is inside the body those steps retire. The
                // owner hands this poller to the reaper, which re-enters shutdown() off-thread. See self_retiring().
                m_running.store(false, std::memory_order_release);
                m_self_retiring.store(true, std::memory_order_release);
                return;
            }

            try
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *seam = g_input_join_fail_seam)
                {
                    seam();
                }
#endif
                m_poll_thread.join();
            }
            catch (...)
            {
                // Poll-thread completion is now uncertain. Detach it, which also prevents a ~jthread rejoin. Keep the
                // module reference and detours because the thread can still read their state.
                m_requires_abandonment.store(true, std::memory_order_release);
                try
                {
                    m_poll_thread.detach();
                }
                catch (...)
                {
                }
                (void)log().try_log(LogLevel::Error,
                                    "InputPoller: poll-thread join failed; abandoning its module reference and "
                                    "leaving the interception detours installed to stay memory-safe.");
                DetourModKit::diagnostics::record_intentional_leak(DetourModKit::diagnostics::LeakSubsystem::Input);
                m_self_ref = nullptr;
                m_running.store(false, std::memory_order_release);
                return;
            }

            // The join completed off the loader lock. Drop the reference taken before thread creation. The active
            // caller for this teardown still holds its own, so this is never the terminal release.
            release_module_ref(static_cast<HMODULE>(m_self_ref));
            m_self_ref = nullptr;

            // The poll thread is provably stopped here. Release of active holds and dispatch of their
            // on_state_change(false) callbacks is race-free.
            m_running.store(false, std::memory_order_release);

            // The poll thread is the sole mask publisher and trampoline reader, so hook teardown now is
            // race-free. Skipped on the loader-lock path above: hook removal must not run under the loader lock,
            // so the detours stay installed there. The owner id makes a superseded poller's teardown a no-op.
            uninstall(m_intercept_owner);

            release_active_holds();

            // This call still has an external owner. Clear the cycle last so that owner destroys the poller only
            // after the worker body and every rundown step can no longer touch it.
            m_owner_keepalive.reset();
        }

        void InputPoller::poll_loop(std::stop_token stop_token)
        {
            const int trigger_thresh = m_trigger_threshold;
            const int stick_thresh = m_stick_threshold;

            constexpr auto gamepad_reconnect_interval = std::chrono::seconds{2};
            bool gamepad_was_connected = false;
            auto last_gamepad_poll = std::chrono::steady_clock::time_point{};

            // Interception state persists across cycles and remains private to the poll thread.
            WheelPulseState wheel_pulse{};
            GamepadSuppressState gp_suppress{};

            // Tracks whether the previous cycle published live gamepad suppression. The disarm below runs exactly
            // once on the arm->disarm transition, which includes removal of the last consume gamepad
            // binding. A plain flag gate skips that transition.
            bool gamepad_suppress_active = false;

            // This state remains private to the poll thread. is_code_pressed reads it only when
            // gamepad_connected is true, which holds only after a successful poll overwrites it.
            XINPUT_STATE gamepad_state{};

            // Per-cycle keyboard/mouse down-state cache (see input_key_cache.hpp). Declared once so its 256-byte
            // table lives for the poll thread's lifetime.
            KeyStateCache key_cache;

            struct PendingCallback
            {
                // Declared first so it is destroyed last, after both std::function members and their capture managers.
                StagedCallbackLease lease;
                std::string name;
                std::function<void()> on_press;
                std::function<void(bool)> on_state_change;
                bool hold_value;
                // The edge's state transition commits only after the whole pass stages every edge. This deferral
                // makes a failed pass leave no edge behind. m_active_states still holds the pre-pass value. The next
                // cycle derives this edge again from unchanged physical input.
                std::size_t state_index = 0;
                std::uint8_t state_value = 0;

                PendingCallback(StagedCallbackLease staged_lease, std::string binding_name,
                                std::function<void()> press_callback, std::function<void(bool)> state_callback,
                                bool next_hold_value, std::size_t next_state_index, std::uint8_t next_state_value)
                    : lease(std::move(staged_lease)), name(std::move(binding_name)),
                      on_press(std::move(press_callback)), on_state_change(std::move(state_callback)),
                      hold_value(next_hold_value), state_index(next_state_index), state_value(next_state_value)
                {
                }
            };
            std::vector<PendingCallback> pending;

            while (!stop_token.stop_requested())
            {
                pending.clear();
                key_cache.reset();
                const bool process_focused =
                    !m_require_focus.load(std::memory_order_relaxed) || is_process_foreground();

                // Install the active-input hooks on demand. Each call is idempotent and fails cheaply until its target
                // appears. The XInput call runs every cycle, not only while coverage is absent. An installed pair
                // can still lose an entry point to a rival writer. A skip based on the published flag hides that loss.
                const bool owns_intercept = intercept_owned_by(m_intercept_owner);
                if (m_has_consume_gamepad_bindings.load(std::memory_order_relaxed))
                {
                    (void)install_xinput(m_gamepad_index, m_intercept_owner);
                }
                const bool has_wheel_bindings = m_has_wheel_bindings.load(std::memory_order_acquire);
                if (has_wheel_bindings && !(owns_intercept && wndproc_installed()))
                {
                    (void)install_wndproc(m_intercept_owner);
                }

                // Republish this poller's cached rules on the cycle that first observes ownership, or the detour
                // otherwise evaluates the rules left by the prior owner. A fresh ownership read here
                // A separate read from owns_intercept lets the first owner cycle also publish.
                if (m_consume_rules_unpublished.load(std::memory_order_acquire) &&
                    intercept_owned_by(m_intercept_owner))
                {
                    std::unique_lock rules_lock(m_bindings_rw_mutex);
                    publish_consume_rules_locked();
                }

                // Accumulate bits that active consume bindings claim this cycle, then publish them after the binding
                // loop. A consume binding masks only what it owns. "Ctrl+WheelUp" contributes Up only while Ctrl is
                // held. Publication each cycle also disarms the mask after the last binding leaves.
                uint16_t gamepad_owned = 0;
                uint8_t wheel_owned = 0;

                // Poll gamepad state once per connected cycle. Throttle reconnection attempts on empty slots.
                // A read through the saved trampoline gives the poll the true, unmasked controller state.
                bool gamepad_connected = false;
                if (m_has_gamepad_bindings.load(std::memory_order_relaxed) && process_focused)
                {
                    const auto now = std::chrono::steady_clock::now();
                    if (gamepad_was_connected || (now - last_gamepad_poll) >= gamepad_reconnect_interval)
                    {
                        last_gamepad_poll = now;
                        // Dereference the saved trampoline only while this poller owns the layer. A non-owner call is
                        // invisible to the detour in-flight drain. It can traverse memory that owner removal frees.
                        // Therefore, a non-owner calls XInputGetState. One fresh check suffices because this thread
                        // cannot lose its own ownership mid-cycle.
                        const XInputGetStateFn xinput_original =
                            intercept_owned_by(m_intercept_owner) ? xinput_trampoline() : nullptr;
                        const DWORD xinput_result =
                            (xinput_original != nullptr)
                                ? xinput_original(static_cast<DWORD>(m_gamepad_index), &gamepad_state)
                                : XInputGetState(static_cast<DWORD>(m_gamepad_index), &gamepad_state);
                        gamepad_was_connected = xinput_result == ERROR_SUCCESS;
                    }
                    gamepad_connected = gamepad_was_connected;
                }

                // Stage this cycle's edge callbacks, then dispatch after release of the binding lock so user code can
                // re-enter update_combos(). The whole stage pass is one transaction under a single catch.
                // Every mutation that a staged edge needs is either staged or restored. A failed pass owes no callback.
                // The next cycle derives the same edges again from unchanged physical input. A binding with no staged
                // edge still commits its state immediately. Otherwise, a key released and struck before the next cycle
                // loses its press.
                WheelPulseState wheel_pulse_staged = wheel_pulse;

                // Arm the swallow mask only for a cycle that also drains the wheel counters. A rebuild failure stops
                // the drain while the consume wheel binding stays in m_bindings. An armed mask then swallows every
                // notch without delivery. That state cannot lapse on its own.
                bool wheel_drained = false;
                try
                {
                    // Re-reserve to the current binding count before acquisition of the evaluation lock. This keeps
                    // the growth allocation outside the critical section. The catch still covers the residual race
                    // where a concurrent add_binding grows the set first.
                    size_t reserve_hint = 0;
                    {
                        std::shared_lock count_lock(m_bindings_rw_mutex);
                        reserve_hint = m_bindings.size();
                    }
                    pending.reserve(reserve_hint);

                    std::shared_lock lock(m_bindings_rw_mutex);
                    const size_t count = m_bindings.size();
                    const auto &known_mods = m_known_modifiers;

                    // Snapshot the accumulated wheel notches into a per-cycle pulse mask so each notch maps to
                    // exactly one Press edge. The poll drains it while unfocused, so a background notch is discarded.
                    // The flag read, drain, and m_bindings snapshot share one shared-lock epoch. No reshape can split
                    // that epoch.
                    uint8_t wheel_pulse_mask = 0;
                    if (m_has_wheel_bindings.load(std::memory_order_relaxed))
                    {
                        const auto taken = take_wheel_counts(m_intercept_owner);
                        add_wheel_notches(wheel_pulse, taken);
                        // Take the rollback point after the drain. Restoration of this snapshot reverses the one-way
                        // step below but preserves drained notches, which have no physical equivalent to repeat.
                        wheel_pulse_staged = wheel_pulse;
                        wheel_pulse_mask = step_wheel_pulse(wheel_pulse);
                        wheel_drained = true;
                    }

                    for (size_t i = 0; i < count; ++i)
                    {
                        const auto &binding = m_bindings[i];
                        if (binding.keys.empty())
                        {
                            continue;
                        }

                        bool any_pressed = false;

                        if (process_focused)
                        {
                            bool modifiers_held = true;
                            for (const auto &mod : binding.modifiers)
                            {
                                if (!is_code_pressed(mod, key_cache, gamepad_state, gamepad_connected, trigger_thresh,
                                                     stick_thresh, wheel_pulse_mask))
                                {
                                    modifiers_held = false;
                                    break;
                                }
                            }

                            if (modifiers_held)
                            {
                                // Enforce an exact modifier set. Reject any known modifier absent from this binding's
                                // required set when it is held.
                                for (const auto &km : known_mods)
                                {
                                    if (!is_code_pressed(km, key_cache, gamepad_state, gamepad_connected,
                                                         trigger_thresh, stick_thresh, wheel_pulse_mask))
                                    {
                                        continue;
                                    }
                                    bool is_required = false;
                                    for (const auto &mod : binding.modifiers)
                                    {
                                        if (modifier_satisfies(mod, km))
                                        {
                                            is_required = true;
                                            break;
                                        }
                                    }
                                    if (!is_required)
                                    {
                                        modifiers_held = false;
                                        break;
                                    }
                                }
                            }

                            if (modifiers_held)
                            {
                                for (const auto &key : binding.keys)
                                {
                                    const bool key_pressed =
                                        is_code_pressed(key, key_cache, gamepad_state, gamepad_connected,
                                                        trigger_thresh, stick_thresh, wheel_pulse_mask);

                                    // Pre-arm the consume bit while the modifiers are held, before the trigger is
                                    // pressed. The mask trails physical state by one cycle. A claim only on a pressed
                                    // trigger leaks its initial edge to the faster game poll.
                                    // A mask for a still-up bit is a no-op, and the consume-until-release latch still
                                    // trails the trigger.
                                    if (binding.consume && key.source == InputSource::Gamepad && key.code > 0 &&
                                        key.code < GamepadCode::LeftTrigger)
                                    {
                                        gamepad_owned =
                                            static_cast<uint16_t>(gamepad_owned | static_cast<uint16_t>(key.code));
                                    }

                                    // Pre-arm the wheel-consume bit while the modifiers are held. The WndProc detour
                                    // decides whether to swallow as soon as a message arrives. The mask must reflect
                                    // "modifiers currently satisfied", not the derived wheel_pulse_mask. This mirrors
                                    // the gamepad pre-arm above.
                                    if (binding.consume && key.source == InputSource::MouseWheel &&
                                        key.code >= WheelCode::Up && key.code <= WheelCode::Right)
                                    {
                                        wheel_owned = static_cast<uint8_t>(
                                            wheel_owned | static_cast<uint8_t>(1u << (key.code - WheelCode::Up)));
                                    }

                                    // Activation still keys off the real press: a non-consume binding fires on the
                                    // first pressed key and stops. A consume binding continues its scan so the
                                    // pre-arm above sees every owned bit.
                                    if (!key_pressed)
                                    {
                                        continue;
                                    }
                                    any_pressed = true;
                                    if (!binding.consume)
                                    {
                                        break;
                                    }
                                }
                            }
                        }

                        const bool was_active = m_active_states[i].load(std::memory_order_relaxed) != 0;
                        const std::uint8_t next_state = any_pressed ? 1 : 0;

                        switch (binding.trigger)
                        {
                        case input::Trigger::Press:
                        {
                            if (any_pressed && !was_active && binding.on_press)
                            {
                                const std::uint64_t generation =
                                    binding.lifecycle ? binding.lifecycle->generation() : 0;
                                StagedCallbackLease lease{binding.lifecycle, generation};
                                if (!lease.engaged())
                                {
                                    continue;
                                }
                                pending.emplace_back(std::move(lease), binding.name, binding.on_press,
                                                     std::function<void(bool)>{}, false, i, next_state);
                                break;
                            }
                            m_active_states[i].store(next_state, std::memory_order_relaxed);
                            break;
                        }
                        case input::Trigger::Hold:
                        {
                            if (any_pressed != was_active && binding.on_state_change)
                            {
                                const std::uint64_t generation =
                                    binding.lifecycle ? binding.lifecycle->generation() : 0;
                                StagedCallbackLease lease{binding.lifecycle, generation};
                                if (!lease.engaged())
                                {
                                    continue;
                                }
                                pending.emplace_back(std::move(lease), binding.name, std::function<void()>{},
                                                     binding.on_state_change, any_pressed, i, next_state);
                                break;
                            }
                            m_active_states[i].store(next_state, std::memory_order_relaxed);
                            break;
                        }
                        }
                    }

                    // Commit: atomic stores only, still under the shared lock, so this cannot fail.
                    for (const auto &staged : pending)
                    {
                        m_active_states[staged.state_index].store(staged.state_value, std::memory_order_relaxed);
                    }
                }
                catch (...)
                {
                    // Roll back every source that a staged edge needs. Return the drained notches to the backlog. Drop
                    // the partial consume masks so suppression disarms wholly.
                    pending.clear();
                    wheel_pulse = wheel_pulse_staged;
                    gamepad_owned = 0;
                    wheel_owned = 0;
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: failed staging poll-cycle callbacks; cycle rolled back");
                }

                // Publish the gamepad suppression mask. The consume-until-release latch keeps a trigger masked until
                // release plus a grace window. Modifier release first cannot leak a bare trigger.
                if (m_has_consume_gamepad_bindings.load(std::memory_order_relaxed) && process_focused &&
                    gamepad_connected)
                {
                    const uint16_t suppress =
                        step_gamepad_suppress(gp_suppress, gamepad_owned, gamepad_state.Gamepad.wButtons,
                                              GetTickCount64(), GAMEPAD_SUPPRESS_GRACE_MS);
                    (void)publish_gamepad_suppress(suppress, m_intercept_owner);
                    // The rule list and its TTL survive focus changes, so the detour needs this explicit gate to
                    // stop suppression after the mod enters the background.
                    (void)set_gamepad_rule_suppress_enabled(true, m_intercept_owner);
                    gamepad_suppress_active = true;
                }
                else if (gamepad_suppress_active)
                {
                    // On exit from armed state due to focus loss, disconnect, or removal of the last consume binding,
                    // disarm once. The game regains the buttons next cycle instead of after the TTL lapses. Publication
                    // only on this edge keeps the idle path free of a per-cycle clock read.
                    gp_suppress = GamepadSuppressState{};
                    (void)publish_gamepad_suppress(0, m_intercept_owner);
                    (void)set_gamepad_rule_suppress_enabled(false, m_intercept_owner);
                    gamepad_suppress_active = false;
                }

                // Publish the per-direction wheel-swallow mask every cycle. Tie it to the drain instead of wheel_owned
                // alone. The mask cannot outlive the loop's ability to deliver the notches it swallows.
                (void)publish_wheel_consume(wheel_drained ? wheel_owned : 0, m_intercept_owner);

#ifdef DMK_ENABLE_TEST_SEAMS
                // Between the stage pass and dispatch, a test reshapes the binding set here. The check below refuses a
                // staged callback after this reshape advances its generation or tombstones its binding.
                if (g_input_post_stage_probe)
                {
                    g_input_post_stage_probe(pending.size());
                }
#endif

                for (auto &callback : pending)
                {
                    // A terminal hold-release (false) edge is admitted even across a generation advance: it only
                    // ends a held state. A dropped edge strands the consumer in its held state. A press or held(true)
                    // edge is still refused once its generation advanced or its registration was tombstoned.
                    const bool admit_across_generation =
                        static_cast<bool>(callback.on_state_change) && !callback.hold_value;
                    const BindingInvocation invocation{callback.lease.lifecycle(), callback.lease.generation(),
                                                       admit_across_generation};
                    if (!invocation.admitted())
                    {
                        continue;
                    }
#ifdef DMK_ENABLE_TEST_SEAMS
                    if (g_input_pre_dispatch_probe)
                    {
                        g_input_pre_dispatch_probe();
                    }
#endif
                    try
                    {
                        if (callback.on_press)
                        {
                            callback.on_press();
                        }
                        else if (callback.on_state_change)
                        {
                            callback.on_state_change(callback.hold_value);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        (void)log().try_log(LogLevel::Error, "InputPoller: Exception in callback \"{}\": {}",
                                            callback.name, e.what());
                    }
                    catch (...)
                    {
                        (void)log().try_log(LogLevel::Error, "InputPoller: Unknown exception in callback \"{}\"",
                                            callback.name);
                    }
                }

                // Destroy staged callable copies before the poll wait. A teardown then observes lease completion
                // immediately instead of one poll interval later.
                pending.clear();

                std::unique_lock lock(m_cv_mutex);
                m_cv.wait_for(lock, stop_token, m_poll_interval,
                              [&stop_token]() { return stop_token.stop_requested(); });
            }
        }

        bool InputPoller::update_combos(std::string_view name, const input::KeyComboList &combos) noexcept
        {
            std::vector<HoldRelease> hold_releases;
            std::vector<BindingRundown> rundowns;

            try
            {
                std::unique_lock lock(m_bindings_rw_mutex);
                const auto it = m_name_index.find(name);
                if (it == m_name_index.end())
                {
                    // Release the writer lock before log output under the deferred-log convention.
                    lock.unlock();
                    (void)log().try_log(LogLevel::Debug, "InputPoller: update_combos(\"{}\") ignored: name not found",
                                        name);
                    return false;
                }

                std::vector<size_t> indices = it->second;
                if (indices.empty())
                {
                    return false;
                }

                // This fast path preserves cardinality. In-place rewrite leaves m_bindings and m_active_states in
                // lockstep. Unlike the rebuild branch, it emits no hold release. The entries preserve their state, so
                // the poll loop emits on_state_change(false) naturally. A synthetic false is invalid for a binding
                // whose rewritten combo remains held.
                if (indices.size() == combos.size())
                {
                    std::vector<InputBinding> replacements;
                    replacements.reserve(indices.size());
                    for (size_t i = 0; i < indices.size(); ++i)
                    {
                        const size_t idx = indices[i];
                        InputBinding binding = m_bindings[idx];
                        binding.keys = combos[i].keys;
                        binding.modifiers = combos[i].modifiers;
                        replacements.push_back(std::move(binding));
                    }
                    rundowns.reserve(indices.size());
                    for (size_t idx : indices)
                    {
                        add_rundown(rundowns, m_bindings[idx].lifecycle);
                    }
                    for (size_t i = 0; i < indices.size(); ++i)
                    {
                        m_bindings[indices[i]] = std::move(replacements[i]);
                    }
                    for (auto &rundown : rundowns)
                    {
                        rundown.generation = rundown.lifecycle->advance_generation();
                    }
                    recompute_modifier_caches_locked();
                    lock.unlock();
                    drain_rundowns(rundowns);
                    return true;
                }

                // A cardinality change rebuilds the bindings vector and the parallel m_active_states array. The
                // prototype keeps callback identity, mode, and name stable across the rebuild. Its lifecycle is
                // held apart so the retained registration receives a new generation instead of a tombstone.
                InputBinding prototype = m_bindings[indices.front()];
                const std::shared_ptr<BindingLifecycle> prototype_lifecycle = prototype.lifecycle;
                std::sort(indices.begin(), indices.end());

                const size_t append_count = combos.empty() ? 1 : combos.size();
                const size_t new_size = m_bindings.size() - indices.size() + append_count;

                // Phase 1 -- allocate everything that can throw without mutation of m_bindings. An empty replacement
                // yields a single inert sentinel so the name stays addressable across a bound -> unbound -> bound
                // INI hot-reload cycle.
                std::vector<InputBinding> appended;
                appended.reserve(append_count);
                if (combos.empty())
                {
                    InputBinding sentinel = prototype;
                    sentinel.keys.clear();
                    sentinel.modifiers.clear();
                    appended.push_back(std::move(sentinel));
                }
                else
                {
                    for (const auto &combo : combos)
                    {
                        InputBinding binding = prototype;
                        binding.keys = combo.keys;
                        binding.modifiers = combo.modifiers;
                        appended.push_back(std::move(binding));
                    }
                }

                std::vector<InputBinding> rebuilt;
                rebuilt.reserve(new_size);
                std::vector<uint8_t> rebuilt_states;
                rebuilt_states.reserve(new_size);
                auto new_states = std::make_unique<std::atomic<uint8_t>[]>(new_size);

                // Capture release callbacks for held entries that this update drops. Otherwise, a Hold consumer remains
                // held forever after its entry vanishes. The same-name NON-prototype tombstone rejects its staged
                // release. Therefore, a gate-backed hold always synthesizes the compensatory false, as remove and clear
                // do. The gate deduplicates, so an unheld drop is a
                // no-op and the prototype's already-admitted release is not doubled.
                hold_releases.reserve(indices.size());
                for (size_t idx : indices)
                {
                    if (m_bindings[idx].trigger == input::Trigger::Hold && m_bindings[idx].on_state_change &&
                        (m_bindings[idx].release_is_idempotent ||
                         m_active_states[idx].load(std::memory_order_relaxed) != 0))
                    {
                        hold_releases.emplace_back(m_bindings[idx].on_state_change, m_bindings[idx].name);
                    }
                }

                rundowns.reserve(indices.size());
                for (size_t idx : indices)
                {
                    add_rundown(rundowns, m_bindings[idx].lifecycle);
                }

                // Phase 2 -- commit. No operation below can throw. Retained entries carry their prior
                // atomic state across the swap so a held binding does not momentarily report inactive.
                size_t cursor = 0;
                for (size_t skip : indices)
                {
                    for (size_t i = cursor; i < skip; ++i)
                    {
                        rebuilt_states.push_back(m_active_states[i].load(std::memory_order_relaxed));
                        rebuilt.push_back(std::move(m_bindings[i]));
                    }
                    cursor = skip + 1;
                }
                for (size_t i = cursor; i < m_bindings.size(); ++i)
                {
                    rebuilt_states.push_back(m_active_states[i].load(std::memory_order_relaxed));
                    rebuilt.push_back(std::move(m_bindings[i]));
                }
                for (auto &binding : appended)
                {
                    rebuilt.push_back(std::move(binding));
                    rebuilt_states.push_back(0);
                }

                for (size_t i = 0; i < rebuilt_states.size(); ++i)
                {
                    new_states[i].store(rebuilt_states[i], std::memory_order_relaxed);
                }

                m_bindings = std::move(rebuilt);
                m_active_states = std::move(new_states);
                for (auto &rundown : rundowns)
                {
                    rundown.generation = rundown.lifecycle == prototype_lifecycle
                                             ? rundown.lifecycle->advance_generation()
                                             : rundown.lifecycle->tombstone();
                }
                recompute_modifier_caches_locked();
            }
            catch (...)
            {
                // Phase 1 allocates before any mutation, so the poller is left unchanged and no callbacks fire.
                (void)log().try_log(LogLevel::Error, "InputPoller: out of memory in update_combos; combos unchanged");
                return false;
            }

            drain_rundowns(rundowns);

            // Fire the captured release callbacks outside the writer lock. This path runs from a user-driven INI
            // reshape, never a DllMain detach, so synchronous dispatch is safe.
            for (auto &[callback, binding_name] : hold_releases)
            {
                try
                {
                    callback(false);
                }
                catch (const std::exception &e)
                {
                    (void)log().try_log(LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}",
                                        binding_name, e.what());
                }
                catch (...)
                {
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: Unknown exception in hold release callback \"{}\"", binding_name);
                }
            }

            return true;
        }

        bool InputPoller::add_binding(InputBinding binding) noexcept
        {
            std::unique_lock lock(m_bindings_rw_mutex);

            const size_t old_count = m_bindings.size();
            const size_t new_count = old_count + 1;

            try
            {
                ensure_lifecycle(binding);

                // Build the replacement state array before mutation of m_bindings so an allocation failure leaves
                // both at their prior equal sizes. A mismatch causes an out-of-bounds poll read. Seed each
                // each retained slot from the current value so a held binding does not flicker inactive.
                auto new_states = std::make_unique<std::atomic<uint8_t>[]>(new_count);
                for (size_t i = 0; i < old_count; ++i)
                {
                    new_states[i].store(m_active_states[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
                }
                new_states[old_count].store(0, std::memory_order_relaxed);

                // push_back has the strong guarantee, so a reallocation failure leaves m_bindings unchanged and
                // simply discards the new_states array.
                m_bindings.push_back(std::move(binding));
                m_active_states = std::move(new_states);
                recompute_modifier_caches_locked();
                return true;
            }
            catch (...)
            {
                // Drop the binding and leave the poller unchanged. The false return lets the facade surface
                // the failure.
                (void)log().try_log(LogLevel::Error, "InputPoller: out of memory in add_binding; binding not added");
                return false;
            }
        }

        bool InputPoller::add_bindings(std::vector<InputBinding> bindings) noexcept
        {
            if (bindings.empty())
            {
                return true;
            }

            std::unique_lock lock(m_bindings_rw_mutex);

            const size_t old_count = m_bindings.size();
            const size_t append_count = bindings.size();
            const size_t new_count = old_count + append_count;

            try
            {
                for (auto &binding : bindings)
                {
                    ensure_lifecycle(binding);
                }

                // Allocate every replacement container before mutation of the live engine. Preserve an atomic
                // multi-combo registration under OOM.
                auto new_states = std::make_unique<std::atomic<uint8_t>[]>(new_count);
                std::vector<InputBinding> rebuilt;
                rebuilt.reserve(new_count);

                for (size_t i = 0; i < old_count; ++i)
                {
                    new_states[i].store(m_active_states[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
                    rebuilt.push_back(std::move(m_bindings[i]));
                }
                for (size_t i = 0; i < append_count; ++i)
                {
                    new_states[old_count + i].store(0, std::memory_order_relaxed);
                    rebuilt.push_back(std::move(bindings[i]));
                }

                m_bindings = std::move(rebuilt);
                m_active_states = std::move(new_states);
                recompute_modifier_caches_locked();
                return true;
            }
            catch (...)
            {
                // All allocation precedes any move from m_bindings, so the live poller remains unchanged.
                (void)log().try_log(LogLevel::Error, "InputPoller: out of memory in add_bindings; bindings not added");
                return false;
            }
        }

        size_t InputPoller::remove_bindings_by_name(std::string_view name, bool invoke_callbacks) noexcept
        {
            std::vector<HoldRelease> hold_releases;
            std::vector<BindingRundown> rundowns;
            size_t removed = 0;

            try
            {
                std::unique_lock lock(m_bindings_rw_mutex);
                const auto it = m_name_index.find(name);
                if (it == m_name_index.end())
                {
                    return 0;
                }

                std::vector<size_t> indices = it->second;
                std::sort(indices.begin(), indices.end());

                // Capture release callbacks before erasure, then dispatch them after unlock. Logic-DLL retirement
                // passes invoke_callbacks=false because the callbacks reside in a module near removal. Always capture a
                // gate-backed hold because the tombstone refuses any staged release. The m_active_states gate strands a
                // consumer whose release is staged but not dispatched. The gate swallows an
                // unbalanced released(false). A raw callback keeps the m_active_states gate.
                if (invoke_callbacks)
                {
                    hold_releases.reserve(indices.size());
                    for (size_t idx : indices)
                    {
                        if (m_bindings[idx].trigger == input::Trigger::Hold && m_bindings[idx].on_state_change &&
                            (m_bindings[idx].release_is_idempotent ||
                             m_active_states[idx].load(std::memory_order_relaxed) != 0))
                        {
                            hold_releases.emplace_back(m_bindings[idx].on_state_change, m_bindings[idx].name);
                        }
                    }
                }

                // A flat skip-mask lets every retained binding inherit its prior atomic state, so a held binding
                // does not briefly report inactive after the reshape.
                std::vector<bool> drop(m_bindings.size(), false);
                for (size_t idx : indices)
                {
                    drop[idx] = true;
                }
                const size_t survivor_count = m_bindings.size() - indices.size();
                std::vector<uint8_t> carried;
                carried.reserve(survivor_count);
                for (size_t i = 0; i < m_bindings.size(); ++i)
                {
                    if (!drop[i])
                    {
                        carried.push_back(m_active_states[i].load(std::memory_order_relaxed));
                    }
                }

                // Allocate the replacement state array before erasure, so an allocation failure leaves m_bindings
                // and m_active_states at their prior equal sizes.
                auto new_states = std::make_unique<std::atomic<uint8_t>[]>(survivor_count);
                for (size_t i = 0; i < carried.size(); ++i)
                {
                    new_states[i].store(carried[i], std::memory_order_relaxed);
                }

                rundowns.reserve(indices.size());
                for (size_t idx : indices)
                {
                    add_rundown(rundowns, m_bindings[idx].lifecycle);
                }
                for (auto &rundown : rundowns)
                {
                    rundown.generation = rundown.lifecycle->tombstone();
                }

                // Commit. The noexcept moves and array swap cannot fail past this point.
                for (auto idx_it = indices.rbegin(); idx_it != indices.rend(); ++idx_it)
                {
                    m_bindings.erase(m_bindings.begin() + static_cast<std::ptrdiff_t>(*idx_it));
                }
                m_active_states = std::move(new_states);
                removed = indices.size();

                recompute_modifier_caches_locked();
            }
            catch (...)
            {
                // Allocation precedes erasure, so the poller is left unchanged and no callbacks fire.
                (void)log().try_log(LogLevel::Error,
                                    "InputPoller: out of memory in remove_bindings_by_name; bindings unchanged");
                return 0;
            }

            // invoke_callbacks == false means the caller owns the wait. The loader-lock abandon path must not block.
            // The typed unload drain bounds the wait on its own deadline. The tombstone is already
            // published, so an in-flight callback is abandoned rather than waited on. Normal removal drains.
            if (invoke_callbacks)
            {
                drain_rundowns(rundowns);
            }

            for (auto &[callback, binding_name] : hold_releases)
            {
                try
                {
                    callback(false);
                }
                catch (const std::exception &e)
                {
                    (void)log().try_log(LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}",
                                        binding_name, e.what());
                }
                catch (...)
                {
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: Unknown exception in hold release callback \"{}\"", binding_name);
                }
            }

            return removed;
        }

        bool InputPoller::retire_gates_by_name(std::string_view name,
                                               std::chrono::steady_clock::time_point deadline) noexcept
        {
            std::vector<std::shared_ptr<BindingGate>> gates;
            try
            {
                std::shared_lock lock(m_bindings_rw_mutex);
                const auto it = m_name_index.find(name);
                if (it == m_name_index.end())
                {
                    return true;
                }
                gates.reserve(it->second.size());
                for (const size_t idx : it->second)
                {
                    if (m_bindings[idx].gate)
                    {
                        gates.push_back(m_bindings[idx].gate);
                    }
                }
            }
            catch (...)
            {
                // Handle collection exhausted memory. Failure is the only truthful result because retirement did not
                // occur. The drain must not tell its caller that the callbacks are gone.
                (void)log().try_log(LogLevel::Error, "InputPoller: out of memory collecting gates for retirement");
                return false;
            }

            return retire_collected_gates(gates, deadline);
        }

        bool InputPoller::retire_all_gates(std::chrono::steady_clock::time_point deadline) noexcept
        {
            std::vector<std::shared_ptr<BindingGate>> gates;
            try
            {
                std::shared_lock lock(m_bindings_rw_mutex);
                gates.reserve(m_bindings.size());
                for (const auto &binding : m_bindings)
                {
                    if (binding.gate)
                    {
                        gates.push_back(binding.gate);
                    }
                }
            }
            catch (...)
            {
                (void)log().try_log(LogLevel::Error, "InputPoller: out of memory collecting gates for retirement");
                return false;
            }

            return retire_collected_gates(gates, deadline);
        }

        bool InputPoller::retire_collected_gates(const std::vector<std::shared_ptr<BindingGate>> &gates,
                                                 std::chrono::steady_clock::time_point deadline) noexcept
        {
            // Off the binding lock: retire() waits out an in-flight delivery, and the poll thread takes the same
            // lock to dispatch. Exploded combos share one gate. retire() is idempotent on the repeat.
            bool retired_all = true;
            for (const auto &gate : gates)
            {
                try
                {
                    if (!gate->retire(deadline))
                    {
                        retired_all = false;
                    }
                }
                catch (const std::exception &e)
                {
                    // The callback is destroyed regardless (retire() moved it out first), so retirement itself
                    // succeeded and only the consumer's edge failed.
                    (void)log().try_log(LogLevel::Error, "InputPoller: Exception in retired hold release callback: {}",
                                        e.what());
                }
                catch (...)
                {
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: Unknown exception in retired hold release callback");
                }
            }
            return retired_all;
        }

        void InputPoller::clear_bindings(bool invoke_callbacks) noexcept
        {
            std::vector<HoldRelease> hold_releases;
            std::vector<BindingRundown> rundowns;

            try
            {
                std::unique_lock lock(m_bindings_rw_mutex);
                // Skip release-callback capture during Logic-DLL retirement: the callbacks live in a module that
                // can start module removal. A gate-backed hold is captured unconditionally. See
                // remove_bindings_by_name.
                if (invoke_callbacks)
                {
                    for (size_t i = 0; i < m_bindings.size(); ++i)
                    {
                        if (m_bindings[i].trigger == input::Trigger::Hold && m_bindings[i].on_state_change &&
                            (m_bindings[i].release_is_idempotent ||
                             m_active_states[i].load(std::memory_order_relaxed) != 0))
                        {
                            hold_releases.emplace_back(m_bindings[i].on_state_change, m_bindings[i].name);
                        }
                    }
                }

                // Allocate the empty replacement before the clear so an allocation failure leaves the poller
                // untouched. Nothing below allocates.
                auto new_states = std::make_unique<std::atomic<uint8_t>[]>(0);

                rundowns.reserve(m_bindings.size());
                for (const auto &binding : m_bindings)
                {
                    add_rundown(rundowns, binding.lifecycle);
                }
                for (auto &rundown : rundowns)
                {
                    rundown.generation = rundown.lifecycle->tombstone();
                }

                m_bindings.clear();
                m_name_index.clear();
                m_known_modifiers.clear();
                // clear_bindings does not route through recompute_modifier_caches_locked, so advance the generation
                // here so live BindingTokens fail closed once the binding set is empty.
                m_binding_generation = next_binding_generation();
                m_has_gamepad_bindings.store(false, std::memory_order_relaxed);
                m_has_wheel_bindings.store(false, std::memory_order_relaxed);
                m_has_consume_gamepad_bindings.store(false, std::memory_order_relaxed);
                m_consume_rules.clear();
                publish_consume_rules_locked();
                m_active_states = std::move(new_states);
            }
            catch (...)
            {
                (void)log().try_log(LogLevel::Error,
                                    "InputPoller: out of memory in clear_bindings; bindings unchanged");
                return;
            }

            // invoke_callbacks == false abandons in-flight callbacks (see remove_bindings_by_name). A normal clear
            // drains.
            if (invoke_callbacks)
            {
                drain_rundowns(rundowns);
            }

            for (auto &[callback, name] : hold_releases)
            {
                try
                {
                    callback(false);
                }
                catch (const std::exception &e)
                {
                    (void)log().try_log(LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}",
                                        name, e.what());
                }
                catch (...)
                {
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: Unknown exception in hold release callback \"{}\"", name);
                }
            }
        }

        void InputPoller::release_active_holds() noexcept
        {
            // Snapshot under the writer lock, then dispatch after its release. The facade can still forward a
            // control-plane add_binding onto this poller because it captured a shared_ptr before shutdown() moved it
            // out. An unlocked read of these containers races that reshape. The collect-then-fire pattern matches
            // remove_bindings_by_name.
            std::vector<HoldRelease> hold_releases;

            bool staging_failed = false;
            try
            {
                std::unique_lock lock(m_bindings_rw_mutex);
                std::size_t release_count = 0;
                for (std::size_t i = 0; i < m_bindings.size(); ++i)
                {
                    const auto &binding = m_bindings[i];
                    if (m_active_states[i].load(std::memory_order_relaxed) != 0 &&
                        binding.trigger == input::Trigger::Hold && binding.on_state_change)
                    {
                        ++release_count;
                    }
                }
                // Allocate before any bit clears, so the staged release commit cannot fail.
                hold_releases.reserve(release_count);
                for (size_t i = 0; i < m_bindings.size(); ++i)
                {
                    if (m_active_states[i].load(std::memory_order_relaxed) == 0)
                    {
                        continue;
                    }
                    const auto &binding = m_bindings[i];
                    if (binding.trigger != input::Trigger::Hold || !binding.on_state_change)
                    {
                        m_active_states[i].store(0, std::memory_order_relaxed);
                        continue;
                    }

                    HoldRelease staged;
                    bool have_callback = false;
                    try
                    {
                        staged.callback = binding.on_state_change;
                        have_callback = true;
                        // Copy the callback first. A name-copy failure costs only its label. A callback-copy failure
                        // costs the consumer its compensatory edge.
                        staged.name = binding.name;
                    }
                    catch (...)
                    {
                        staging_failed = true;
                    }
                    if (!have_callback)
                    {
                        // Nothing to deliver, so leave the bit set rather than advertise a release that never happened.
                        continue;
                    }
                    hold_releases.push_back(std::move(staged));
                    // Cleared only now: the bit is the sole record that this binding is held, and a release is
                    // guaranteed staged from here.
                    m_active_states[i].store(0, std::memory_order_relaxed);
                }
            }
            catch (...)
            {
                staging_failed = true;
            }

            if (staging_failed)
            {
                // Report and continue. Every staged release still runs below.
                (void)log().try_log(LogLevel::Error, "InputPoller: out of memory staging hold-release callbacks");
            }

            for (auto &[callback, name] : hold_releases)
            {
                try
                {
                    callback(false);
                }
                catch (const std::exception &e)
                {
                    (void)log().try_log(LogLevel::Error, "InputPoller: Exception in hold release callback \"{}\": {}",
                                        name, e.what());
                }
                catch (...)
                {
                    (void)log().try_log(LogLevel::Error,
                                        "InputPoller: Unknown exception in hold release callback \"{}\"", name);
                }
            }
        }

        bool InputPoller::is_process_foreground() const noexcept
        {
            HWND foreground = GetForegroundWindow();
            if (!foreground)
            {
                return false;
            }
            DWORD foreground_pid = 0;
            GetWindowThreadProcessId(foreground, &foreground_pid);
            return foreground_pid == GetCurrentProcessId();
        }
    } // namespace detail
} // namespace DetourModKit
