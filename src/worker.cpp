#include "DetourModKit/worker.hpp"
#include "DetourModKit/logger.hpp"
#include "platform.hpp"

#include <utility>

namespace DetourModKit
{
    StoppableWorker::StoppableWorker(std::string_view name,
                                     std::function<void(std::stop_token)> body)
        : name_(name)
    {
        if (!body)
        {
            Logger::get_instance().error(
                "StoppableWorker '{}': empty body; no thread started.", name_);
            joined_.store(true, std::memory_order_release);
            return;
        }

        thread_ = std::jthread(
            [fn = std::move(body), label = name_](std::stop_token st)
            {
                try
                {
                    fn(st);
                }
                catch (const std::exception &e)
                {
                    Logger::get_instance().error(
                        "StoppableWorker '{}': unhandled exception: {}", label, e.what());
                }
                catch (...)
                {
                    Logger::get_instance().error(
                        "StoppableWorker '{}': unknown exception escaped body.", label);
                }
            });

        Logger::get_instance().debug("StoppableWorker '{}' started.", name_);
    }

    StoppableWorker::~StoppableWorker() noexcept
    {
        shutdown();
    }

    void StoppableWorker::request_stop() noexcept
    {
        if (thread_.joinable())
        {
            thread_.request_stop();
        }
    }

    bool StoppableWorker::is_running() const noexcept
    {
        return thread_.joinable() && !joined_.load(std::memory_order_acquire);
    }

    void StoppableWorker::shutdown() noexcept
    {
        bool expected = false;
        if (!joined_.compare_exchange_strong(expected, true,
                                             std::memory_order_acq_rel))
        {
            return;
        }

        if (!thread_.joinable())
        {
            return;
        }

        thread_.request_stop();

        if (detail::is_loader_lock_held())
        {
            detail::pin_current_module();
            thread_.detach();
            return;
        }

        thread_.join();
    }
} // namespace DetourModKit
