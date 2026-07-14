#ifndef DETOURMODKIT_INTERNAL_LIFECYCLE_CONTEXT_HPP
#define DETOURMODKIT_INTERNAL_LIFECYCLE_CONTEXT_HPP

#include <atomic>
#include <cstdint>

// Keep the lifecycle control block independent of the Win32 headers while retaining HMODULE's exact pointer type.
struct HINSTANCE__;

namespace DetourModKit::detail
{
    /// Represents the serialized session phase.
    enum class LifecycleState : std::uint8_t
    {
        Stopped,
        Starting,
        Running,
        Stopping
    };

    /**
     * @brief Identifies the loader phase published by the controlled bootstrap path.
     * @note This context authorizes teardown behavior; loader-lock detection may only veto blocking work.
     */
    enum class LoaderContext : std::uint8_t
    {
        Normal,
        Attach,
        Detach,
        ProcessExit
    };

    /**
     * @class LifecycleContext
     * @brief The session lifecycle control block. All fields are lock-free atomics so any getter is race-free against a
     *        concurrent detach-path write.
     */
    class LifecycleContext
    {
    public:
        using Module = ::HINSTANCE__ *;

        /// Returns the atomically published module identity, or null.
        [[nodiscard]] Module module() const noexcept { return m_module.load(std::memory_order_acquire); }
        /// Publishes the module identity.
        void publish_module(Module module) noexcept { m_module.store(module, std::memory_order_release); }
        /// Clears the module identity.
        void clear_module() noexcept { m_module.store(nullptr, std::memory_order_release); }

        /// Returns the current session phase.
        [[nodiscard]] LifecycleState state() const noexcept { return m_state.load(std::memory_order_acquire); }
        /// Returns the monotonically increasing session generation.
        [[nodiscard]] std::uint64_t generation() const noexcept { return m_generation.load(std::memory_order_acquire); }

        /**
         * @brief Claims the single-session slot: Stopped -> Starting, bumping the generation and resetting the loader
         *        context to Normal for the new epoch.
         * @return true if the slot was free; false if a session is already Starting, Running, or Stopping (the caller
         *         reports SessionAlreadyActive).
         */
        [[nodiscard]] bool begin_start() noexcept;
        /// Starting -> Running once setup has succeeded.
        void mark_running() noexcept;
        /// Running -> Stopping at the start of teardown; a concurrent start stays rejected through the whole teardown.
        void begin_stop() noexcept;
        /// -> Stopped from any state (teardown complete, or a start-setup failure rollback).
        void mark_stopped() noexcept;

        [[nodiscard]] LoaderContext loader_context() const noexcept
        {
            return m_loader_context.load(std::memory_order_acquire);
        }
        void set_loader_context(LoaderContext context) noexcept
        {
            m_loader_context.store(context, std::memory_order_release);
        }

    private:
        std::atomic<Module> m_module{nullptr};
        std::atomic<LifecycleState> m_state{LifecycleState::Stopped};
        std::atomic<std::uint64_t> m_generation{0};
        std::atomic<LoaderContext> m_loader_context{LoaderContext::Normal};
    };

    // module_handle() is callback-safe and therefore cannot use an atomic implementation backed by a hidden lock.
    static_assert(std::atomic<LifecycleContext::Module>::is_always_lock_free,
                  "the module identity must be a lock-free atomic pointer.");

    /// The one process-global session control block.
    [[nodiscard]] LifecycleContext &lifecycle() noexcept;
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_LIFECYCLE_CONTEXT_HPP
