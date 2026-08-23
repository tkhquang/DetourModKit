// Producer enqueue-latency microbenchmark for the async logger. It measures per-enqueue latency percentiles under a
// streaming workload where the writer is actively draining, i.e. the callback-safe producer hot path. A producer
// signals a parked writer without a control-plane mutex and skips the syscall while the writer is busy. Prints one TSV
// row per workload plus the gate records described in bench_gate.hpp to stdout.
//
// Three rows, because the overflow policy changes what the producer does at the full-queue step (B1). DropOldest
// evicts a queued record and can take the string-pool lock; DropNewest refuses and returns. The third row runs the
// public Logger::log() producer under DropNewest, so the difference between it and the raw enqueue row is the
// formatting and dispatch the facade adds on top of the same queue step.

#include "DetourModKit/async_logger_config.hpp"
#include "DetourModKit/logger.hpp"

#include "bench_gate.hpp"
#include "internal/async_logger.hpp"
#include "internal/win_file_stream.hpp"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

using namespace DetourModKit;
using namespace std::chrono;

namespace
{
    constexpr int WARMUP = 50000;
    constexpr int SAMPLES = 500000;

    struct Run
    {
        std::vector<long long> latencies;
        std::size_t accepted = 0;
        std::size_t dropped = 0;
    };

    [[nodiscard]] long long percentile(const std::vector<long long> &sorted, double fraction) noexcept
    {
        return sorted[static_cast<std::size_t>(fraction * static_cast<double>(sorted.size() - 1))];
    }

    // Times SAMPLES calls of @p produce, which must return whether the record reached the queue.
    [[nodiscard]] Run sample(auto &&produce)
    {
        Run run;
        run.latencies.reserve(SAMPLES);
        for (int i = 0; i < WARMUP; ++i)
        {
            (void)produce("warmup");
        }
        for (int i = 0; i < SAMPLES; ++i)
        {
            const auto start = steady_clock::now();
            const bool queued = produce("bench streaming producer latency sample");
            const auto end = steady_clock::now();
            run.latencies.push_back(duration_cast<nanoseconds>(end - start).count());
            run.accepted += queued ? 1u : 0u;
        }
        std::sort(run.latencies.begin(), run.latencies.end());
        return run;
    }

    void print_row(const char *workload, const char *policy, const Run &run) noexcept
    {
        std::printf(
            "%s\t%s\t%d\t%lld\t%lld\t%lld\t%lld\t%zu\t%zu\n",
            workload,
            policy,
            SAMPLES,
            percentile(run.latencies, 0.50),
            percentile(run.latencies, 0.99),
            percentile(run.latencies, 0.999),
            run.latencies.back(),
            run.accepted,
            run.dropped
        );
    }

    [[nodiscard]] std::filesystem::path sink_path_for(const char *tag)
    {
        return std::filesystem::temp_directory_path() /
               ("detourmodkit_logger_bench_" + std::string{tag} + "_" + std::to_string(GetCurrentProcessId()) + ".log");
    }

    [[nodiscard]] AsyncLoggerConfig bench_config(OverflowPolicy policy) noexcept
    {
        AsyncLoggerConfig config;
        config.queue_capacity = 8192;
        config.batch_size = 64;
        config.flush_interval = milliseconds{5};
        config.overflow_policy = policy;
        return config;
    }

    // Drives one AsyncLogger to completion against its own sink file and removes the file afterwards.
    [[nodiscard]] Run run_async_logger(const char *tag, OverflowPolicy policy)
    {
        const auto sink_path = sink_path_for(tag);
        std::error_code error_code;
        std::filesystem::remove(sink_path, error_code);
        auto file_stream = std::make_shared<detail::WinFileStream>(sink_path.string());
        auto log_mutex = std::make_shared<std::mutex>();
        AsyncLogger logger(bench_config(policy), file_stream, log_mutex);

        Run run = sample([&logger](const char *message) { return logger.enqueue(LogLevel::Info, message); });
        run.dropped = logger.dropped_count();

        logger.flush();
        logger.shutdown();
        file_stream->close();
        std::filesystem::remove(sink_path, error_code);
        return run;
    }

    // Drives the public facade rather than the queue directly, so the row carries the formatting and dispatch cost a
    // caller of log() actually pays.
    [[nodiscard]] Run run_public_logger(const char *tag, OverflowPolicy policy)
    {
        const auto sink_path = sink_path_for(tag);
        std::error_code error_code;
        std::filesystem::remove(sink_path, error_code);

        Run run;
        {
            Logger logger("bench", sink_path.string());
            logger.enable_async_mode(bench_config(policy));
            run = sample([&logger](const char *message) { return logger.log(LogLevel::Info, message); });
            run.dropped = logger.dropped_count();
            logger.shutdown();
        }
        std::filesystem::remove(sink_path, error_code);
        return run;
    }
} // namespace

int main()
{
    dmk_bench::GateLedger gates("logger");

    const Run drop_oldest = run_async_logger("drop_oldest", OverflowPolicy::DropOldest);
    const Run drop_newest = run_async_logger("drop_newest", OverflowPolicy::DropNewest);
    const Run public_newest = run_public_logger("public_newest", OverflowPolicy::DropNewest);

    std::printf("workload\tpolicy\tsamples\tp50_ns\tp99_ns\tp999_ns\tmax_ns\taccepted\tdropped\n");
    print_row("enqueue_streaming", "DropOldest", drop_oldest);
    print_row("enqueue_streaming", "DropNewest", drop_newest);
    print_row("log_public", "DropNewest", public_newest);

    // The percentile table is meaningless if the producer never actually reached the queue. Saturating it is the
    // point of this workload, so a large drop count is expected and is not a failure; zero accepted enqueues is,
    // because then every latency below timed a refusal rather than the callback-safe producer path.
    gates.fact("logger.sample_count_complete", drop_oldest.latencies.size() == static_cast<std::size_t>(SAMPLES));
    gates.fact("logger.enqueue_reached_the_queue", drop_oldest.accepted != 0);
    gates.fact("logger.drop_newest_reached_the_queue", drop_newest.accepted != 0);
    gates.fact("logger.public_log_reached_the_queue", public_newest.accepted != 0);
    gates.metric("logger.enqueue_accepted", static_cast<double>(drop_oldest.accepted));
    gates.metric("logger.p99_ns", static_cast<double>(percentile(drop_oldest.latencies, 0.99)));
    gates.metric("logger.drop_newest_p99_ns", static_cast<double>(percentile(drop_newest.latencies, 0.99)));
    gates.metric(
        "logger.public_log_drop_newest_p99_ns",
        static_cast<double>(percentile(public_newest.latencies, 0.99))
    );
    return gates.close();
}
