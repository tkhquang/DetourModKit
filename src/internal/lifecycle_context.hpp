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
     * @details This context authorizes blocking teardown for threads the process cannot identify individually;
     *          loader-lock detection may only veto it. @ref ExplicitDrain and @ref LoaderDetach are deliberately
     *          distinct: both follow a consumer's decision to unload, but only the first runs on a thread that is
     *          outside a loader callback and may therefore join.
     */
    enum class LoaderContext : std::uint8_t
    {
        /// No loader callback is in progress; a normally-hosted session.
        Normal,
        /// Inside DllMain DLL_PROCESS_ATTACH.
        Attach,
        /// An off-loader-lock shutdown handshake. The only unload phase that may block.
        ExplicitDrain,
        /// Inside DllMain DLL_PROCESS_DETACH for an explicit FreeLibrary.
        LoaderDetach,
        /// Inside DllMain DLL_PROCESS_DETACH for process termination.
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

        /**
         * @brief Reports whether the published context permits a teardown to block (join, wait, run user destruction).
         * @details Only @ref LoaderContext::Normal and @ref LoaderContext::ExplicitDrain qualify. This is one of the
         *          two authorizing halves of the decision; callers must use @ref blocking_teardown_permitted, which
         *          also admits the bootstrap worker and applies the fail-closed loader-lock veto.
         */
        [[nodiscard]] bool context_permits_blocking() const noexcept
        {
            const LoaderContext context = loader_context();
            return context == LoaderContext::Normal || context == LoaderContext::ExplicitDrain;
        }

        /// Publishes the calling thread as the bootstrap worker. Called by the worker before consumer code can run.
        void publish_worker_thread() noexcept;
        /**
         * @brief Retires the published worker identity.
         * @details Required before the worker's id can be recycled by the OS, or a later unrelated thread would inherit
         *          both its blocking authorization and its refused self-drain.
         */
        void clear_worker_thread() noexcept;
        /// The published bootstrap worker's OS thread id, or 0 when no worker is published.
        [[nodiscard]] std::uint32_t worker_thread_id() const noexcept
        {
            return m_worker_thread_id.load(std::memory_order_acquire);
        }
        /// Reports whether the calling thread is the published bootstrap worker.
        [[nodiscard]] bool is_worker_thread() const noexcept;

    private:
        std::atomic<Module> m_module{nullptr};
        std::atomic<LifecycleState> m_state{LifecycleState::Stopped};
        std::atomic<std::uint64_t> m_generation{0};
        std::atomic<LoaderContext> m_loader_context{LoaderContext::Normal};
        std::atomic<std::uint32_t> m_worker_thread_id{0};
    };

    // module_handle() is callback-safe and therefore cannot use an atomic implementation backed by a hidden lock.
    static_assert(std::atomic<LifecycleContext::Module>::is_always_lock_free,
                  "the module identity must be a lock-free atomic pointer.");

    /// The one process-global session control block.
    [[nodiscard]] LifecycleContext &lifecycle() noexcept;

    /**
     * @brief Reports whether the caller is authorized to block, before the loader-lock veto is applied.
     * @details Either the published phase authorizes every thread (@ref LifecycleContext::context_permits_blocking),
     *          or the caller is the bootstrap worker. The worker needs its own clause because the loader context is one
     *          process-global word describing the DllMain thread's phase: a bare FreeLibrary publishes
     *          @ref LoaderContext::LoaderDetach and returns, and the worker then runs the ordered teardown it was
     *          created to run on a thread that is in no loader callback and still holds a counted module reference.
     *          Widening the published phase instead would authorize every other thread for that whole window.
     */
    [[nodiscard]] bool teardown_caller_authorized() noexcept;

    /**
     * @brief The single gate every teardown must pass before it joins a thread, waits, closes a sink, or destroys
     *        callable state that may run consumer code.
     * @details Combines both halves of the rule in one call so no site can apply only one: the caller must be
     *          authorized (@ref teardown_caller_authorized), AND the fail-closed loader-lock diagnostic must not veto
     *          it. A heuristic false alone never authorizes blocking, which is why this is a function rather than a
     *          bare `!is_loader_lock_held()` at each call site.
     * @return true only when blocking teardown is safe; false means take the abandon/retain path.
     */
    [[nodiscard]] bool blocking_teardown_permitted() noexcept;

    /**
     * @brief @ref blocking_teardown_permitted with the loader-lock probe replaced by a test-installed override.
     * @param probe_override The subsystem's override hook, or nullptr to use the real probe.
     * @details Subsystems that expose their own probe seam route through this rather than composing the two halves
     *          locally, so the authorization rule has exactly one definition. A forced "held" still vetoes; a forced
     *          "not held" only withdraws the veto, because a heuristic false never authorizes blocking on its own.
     */
    [[nodiscard]] inline bool blocking_teardown_permitted(bool (*probe_override)() noexcept) noexcept
    {
        if (probe_override != nullptr)
        {
            return teardown_caller_authorized() && !probe_override();
        }
        return blocking_teardown_permitted();
    }
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_LIFECYCLE_CONTEXT_HPP
