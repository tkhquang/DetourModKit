#ifndef DETOURMODKIT_INTERNAL_WORKER_START_LOG_HPP
#define DETOURMODKIT_INTERNAL_WORKER_START_LOG_HPP

#include <source_location>
#include <string_view>

namespace DetourModKit::detail
{
    /**
     * @class WorkerStartLogDeferral
     * @brief Defers the StoppableWorker constructor record on the current thread.
     * @details The context must remain alive until scope destruction. The sink must accept that context type and must
     *          not throw.
     */
    class WorkerStartLogDeferral
    {
    public:
        using Sink = void (*)(void *, std::string_view, std::source_location) noexcept;

        /**
         * @brief Enters one nested deferral scope.
         * @param context The sink context for this scope.
         * @param sink The no-throw adapter that records one canonical start line.
         */
        WorkerStartLogDeferral(void *context, Sink sink) noexcept
            : m_context(context), m_sink(sink), m_previous(current())
        {
            current() = this;
        }

        /// Leaves one nested deferral scope.
        ~WorkerStartLogDeferral() noexcept { current() = m_previous; }

        WorkerStartLogDeferral(const WorkerStartLogDeferral &) = delete;
        WorkerStartLogDeferral &operator=(const WorkerStartLogDeferral &) = delete;

        /**
         * @brief Routes one start line through the current deferral scope.
         * @param name The worker name.
         * @param where The original record source.
         * @return true if a scope consumed the record, even when its sink recorded a drop.
         */
        [[nodiscard]] static bool defer_start(std::string_view name, std::source_location where) noexcept
        {
            WorkerStartLogDeferral *scope = current();
            if (scope == nullptr || scope->m_sink == nullptr)
            {
                return false;
            }
            scope->m_sink(scope->m_context, name, where);
            return true;
        }

    private:
        [[nodiscard]] static WorkerStartLogDeferral *&current() noexcept
        {
            static thread_local WorkerStartLogDeferral *s_current = nullptr;
            return s_current;
        }

        void *m_context;
        Sink m_sink;
        WorkerStartLogDeferral *m_previous;
    };
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_WORKER_START_LOG_HPP
