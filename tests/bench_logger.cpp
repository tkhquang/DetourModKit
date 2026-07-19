// Producer enqueue-latency microbenchmark for the async logger. It measures per-enqueue latency percentiles under a
// streaming workload where the writer is actively draining, i.e. the callback-safe producer hot path. A producer
// signals a parked writer without a control-plane mutex and skips the syscall while the writer is busy. Prints one TSV
// row to stdout.

#include "DetourModKit/logger.hpp"

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
#include <vector>

using namespace DetourModKit;
using namespace std::chrono;

int main()
{
    AsyncLoggerConfig config;
    config.queue_capacity = 8192;
    config.batch_size = 64;
    config.flush_interval = milliseconds{5};
    config.overflow_policy = OverflowPolicy::DropOldest;

    const auto sink_path = std::filesystem::temp_directory_path() /
                           ("detourmodkit_logger_bench_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(sink_path, error_code);
    auto file_stream = std::make_shared<detail::WinFileStream>(sink_path.string());
    auto log_mutex = std::make_shared<std::mutex>();
    AsyncLogger logger(config, file_stream, log_mutex);

    constexpr int WARMUP = 50000;
    constexpr int SAMPLES = 500000;

    for (int i = 0; i < WARMUP; ++i)
    {
        (void)logger.enqueue(LogLevel::Info, "warmup");
    }

    std::vector<long long> latencies;
    latencies.reserve(SAMPLES);
    for (int i = 0; i < SAMPLES; ++i)
    {
        const auto start = steady_clock::now();
        (void)logger.enqueue(LogLevel::Info, "bench streaming producer latency sample");
        const auto end = steady_clock::now();
        latencies.push_back(duration_cast<nanoseconds>(end - start).count());
    }

    const std::size_t dropped = logger.dropped_count();
    logger.flush();
    logger.shutdown();
    file_stream->close();
    std::filesystem::remove(sink_path, error_code);

    std::sort(latencies.begin(), latencies.end());
    const auto percentile = [&](double fraction) -> long long
    {
        const auto index = static_cast<std::size_t>(fraction * static_cast<double>(latencies.size() - 1));
        return latencies[index];
    };

    std::printf("workload\tsamples\tp50_ns\tp99_ns\tp999_ns\tmax_ns\tdropped\n");
    std::printf("enqueue_streaming\t%d\t%lld\t%lld\t%lld\t%lld\t%zu\n", SAMPLES, percentile(0.50),
                percentile(0.99), percentile(0.999), latencies.back(), dropped);
    return 0;
}
