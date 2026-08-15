/**
 * @file bench_footprint.cpp
 * @brief Runtime footprint measurement for the async logger and the profiler, per linked DMK instance.
 *
 * P2-4 requires the actual high-water and resident bytes of the logger/profiler defaults to be measured
 * before any capacity default changes; static footprint estimates alone must not tune them. This benchmark
 * measures, with the counting allocator from bench_alloc.hpp plus OS process counters:
 *
 *   [1] AsyncLogger construction at default config: C++ heap delta, private-commit delta, and the transport
 *       slot size the queue multiplies (sizeof LogMessage x queue_capacity).
 *   [2] Inline-path streaming: allocations per enqueue across producer and writer while the writer drains
 *       (the callback-relevant figure is the producer path; the combined figure is the whole-system cost).
 *   [3] Over-inline overflow: StringPool growth and the high-water while long records are in flight.
 *   [4] Logger shutdown: released vs retained bytes (the StringPool singleton is a documented bounded leak).
 *   [5] Profiler first use: the published ring's resident bytes (capacity x sizeof ProfileSample), the
 *       allocation-free record path, and the export cost per resident sample.
 *
 * Both subsystems are per linked DMK instance, so a host with N DMK-linked mods multiplies these figures.
 * Build with -DDMK_BUILD_BENCHMARKS=ON. Executable: DetourModKit_bench_footprint. Output: human-readable
 * figures plus #TSV rows and the gate records described in bench_gate.hpp.
 */

#include "DetourModKit/logger.hpp"
#include "DetourModKit/profiler.hpp"
#include "DetourModKit/detail/profile_ring.hpp"

#include "bench_gate.hpp"
#include "internal/async_logger.hpp"
#include "internal/async_logger_queue.hpp"
#include "internal/win_file_stream.hpp"

#define PSAPI_VERSION 2
#include <windows.h>
#include <psapi.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#define DMK_BENCH_COUNT_ALLOCATIONS
#include "bench_alloc.hpp"

namespace
{
    using namespace DetourModKit;

    struct ProcessMemory
    {
        std::uint64_t private_bytes;
        std::uint64_t working_set_bytes;
    };

    ProcessMemory process_memory(dmk_bench::GateLedger &gates, const char *failure_gate)
    {
        PROCESS_MEMORY_COUNTERS_EX counters{};
        counters.cb = sizeof(counters);
        if (K32GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&counters),
                                    sizeof(counters)) == 0)
        {
            std::fprintf(stderr, "[bench] GetProcessMemoryInfo failed: %lu\n", GetLastError());
            gates.abort_setup(failure_gate);
        }
        return {static_cast<std::uint64_t>(counters.PrivateUsage), static_cast<std::uint64_t>(counters.WorkingSetSize)};
    }

    /**
     * @brief Snapshot delta clamped at zero: process commit can shrink between snapshots, and a concurrent
     *        writer thread can free between a baseline read and its paired reset_peak().
     */
    std::uint64_t delta_clamped(std::uint64_t after, std::uint64_t before) noexcept
    {
        return after > before ? after - before : 0;
    }

    /// Lets the writer drain and the heap settle so a following snapshot is not racing in-flight batches.
    void quiesce(AsyncLogger &logger)
    {
        logger.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
} // namespace

int main()
{
    dmk_bench::GateLedger gates("footprint");
    (void)process_memory(gates, "footprint.process_counters_available");
    gates.fact("footprint.process_counters_available", true);

    std::printf("DetourModKit runtime footprint (per linked DMK instance)\n");
    std::printf("  sizeof(detail::LogMessage)    = %zu bytes (inline buffer %zu)\n", sizeof(detail::LogMessage),
                static_cast<std::size_t>(LOG_INLINE_MESSAGE_SIZE));
    std::printf("  sizeof(detail::ProfileSample) = %zu bytes\n", sizeof(detail::ProfileSample));
    std::printf("  DEFAULT_QUEUE_CAPACITY        = %zu slots\n", DEFAULT_QUEUE_CAPACITY);
    std::printf("  Profiler::DEFAULT_CAPACITY    = %zu samples\n",
                static_cast<std::size_t>(Profiler::DEFAULT_CAPACITY));

    // Phase 1: async logger construction at defaults. The queue ring is the dominant static cost:
    // queue_capacity slots each embedding a LogMessage.
    const auto sink_path = std::filesystem::temp_directory_path() /
                           ("detourmodkit_footprint_bench_" + std::to_string(GetCurrentProcessId()) + ".log");
    std::error_code error_code;
    std::filesystem::remove(sink_path, error_code);

    const std::uint64_t live_before_logger = dmk_alloc::live_bytes();
    const ProcessMemory os_before_logger = process_memory(gates, "footprint.process_counters_stable");
    dmk_alloc::reset_peak();

    AsyncLoggerConfig config; // defaults throughout: the measurement subject
    auto file_stream = std::make_shared<detail::WinFileStream>(sink_path.string());
    auto log_mutex = std::make_shared<std::mutex>();
    auto logger = std::make_unique<AsyncLogger>(config, file_stream, log_mutex);
    gates.fact("footprint.logger_constructed", logger->is_running());

    const std::uint64_t logger_init_bytes = dmk_alloc::live_bytes() - live_before_logger;
    const ProcessMemory os_after_logger = process_memory(gates, "footprint.process_counters_stable");
    const std::uint64_t logger_private_bytes =
        delta_clamped(os_after_logger.private_bytes, os_before_logger.private_bytes);
    std::printf("\n[1] AsyncLogger construction (defaults)\n");
    std::printf("  C++ heap delta:        %10llu bytes\n", static_cast<unsigned long long>(logger_init_bytes));
    std::printf("  private-commit delta:  %10llu bytes\n", static_cast<unsigned long long>(logger_private_bytes));
    std::printf("  queue slots x slot size: %zu x %zu = %zu bytes\n", config.queue_capacity, sizeof(detail::LogMessage),
                config.queue_capacity * sizeof(detail::LogMessage));

    // Phase 2: inline-path streaming. Messages within LOG_INLINE_MESSAGE_SIZE ride in the slot's inline
    // buffer; the counter delta divided by messages is the whole-system allocation cost per message,
    // producer and writer combined (the two cannot be split by a global counter, and the writer IS part of
    // the per-message cost the host pays).
    constexpr int INLINE_MESSAGES = 200000;
    std::size_t inline_accepted = 0;
    quiesce(*logger);
    const std::uint64_t allocs_before_inline = dmk_alloc::g_alloc_calls.load(std::memory_order_relaxed);
    for (int i = 0; i < INLINE_MESSAGES; ++i)
    {
        inline_accepted += logger->enqueue(LogLevel::Info, "inline footprint sample within the buffer") ? 1u : 0u;
    }
    quiesce(*logger);
    const std::uint64_t inline_allocs = dmk_alloc::g_alloc_calls.load(std::memory_order_relaxed) - allocs_before_inline;
    // Per accepted message: a rejected enqueue never reaches the queue, so it must not dilute the metric.
    // The accepted-nonzero fact below already fails the run when the divisor guard publishes 0.
    const double allocs_per_inline =
        inline_accepted != 0 ? static_cast<double>(inline_allocs) / static_cast<double>(inline_accepted) : 0.0;
    gates.fact("footprint.logger_inline_accepted_nonzero", inline_accepted != 0);
    std::printf("\n[2] Inline streaming (%d messages, writer draining)\n", INLINE_MESSAGES);
    std::printf("  accepted: %zu   allocations/message (producer+writer): %.4f\n", inline_accepted, allocs_per_inline);

    // Phase 3: over-inline overflow. Each long record takes a StringPool slot (or a heap fallback); the
    // growth and the high-water bound what a burst of long records costs while in flight.
    constexpr int LONG_MESSAGES = 5000;
    const std::string long_message(2048, 'x');
    const std::uint64_t live_before_long = dmk_alloc::live_bytes();
    dmk_alloc::reset_peak();
    std::size_t long_accepted = 0;
    for (int i = 0; i < LONG_MESSAGES; ++i)
    {
        long_accepted += logger->enqueue(LogLevel::Info, long_message) ? 1u : 0u;
    }
    quiesce(*logger);
    const std::uint64_t long_peak = delta_clamped(dmk_alloc::peak_live_bytes(), live_before_long);
    const std::uint64_t long_retained = delta_clamped(dmk_alloc::live_bytes(), live_before_long);
    gates.fact("footprint.logger_overflow_accepted_nonzero", long_accepted != 0);
    std::printf("\n[3] Over-inline streaming (%d x %zu-byte messages)\n", LONG_MESSAGES, long_message.size());
    std::printf("  accepted: %zu   high-water: %llu bytes   retained after drain: %llu bytes\n", long_accepted,
                static_cast<unsigned long long>(long_peak), static_cast<unsigned long long>(long_retained));

    // Phase 4: shutdown. The queue and writer state release; the StringPool singleton is the documented
    // bounded leak (MEMORY_POOL_BLOCK_COUNT blocks maximum) and stays for process life.
    logger->flush();
    logger->shutdown();
    logger.reset();
    file_stream->close();
    file_stream.reset();
    std::filesystem::remove(sink_path, error_code);
    const std::uint64_t logger_retained = dmk_alloc::live_bytes() - live_before_logger;
    std::printf("\n[4] After logger shutdown\n");
    std::printf("  retained vs pre-construction: %llu bytes (StringPool singleton and sink bookkeeping)\n",
                static_cast<unsigned long long>(logger_retained));

    // Phase 5: profiler. First use publishes the full default ring, which then stays resident for process
    // life (the instance is deliberately never destroyed). The record path must not allocate: it is the
    // documented lock-free hot path, so its allocation count is a deterministic gate, measured with no other
    // thread running.
    const std::uint64_t live_before_profiler = dmk_alloc::live_bytes();
    Profiler &profiler = Profiler::get_instance();
    const std::uint64_t profiler_bytes = dmk_alloc::live_bytes() - live_before_profiler;
    gates.fact("footprint.profiler_ring_published", profiler.capacity() == Profiler::DEFAULT_CAPACITY);
    std::printf("\n[5] Profiler first use\n");
    std::printf("  ring resident: %llu bytes (%zu samples x %zu bytes)\n",
                static_cast<unsigned long long>(profiler_bytes), profiler.capacity(), sizeof(detail::ProfileSample));

    const std::uint64_t allocs_before_record = dmk_alloc::g_alloc_calls.load(std::memory_order_relaxed);
    const std::uint32_t thread_id = GetCurrentThreadId();
    for (int i = 0; i < 100000; ++i)
    {
        profiler.record("footprint", i, i + 10, thread_id);
    }
    const std::uint64_t record_allocs = dmk_alloc::g_alloc_calls.load(std::memory_order_relaxed) - allocs_before_record;
    gates.fact("footprint.profiler_record_allocation_free", record_allocs == 0);
    std::printf("  100000 record() calls: %llu allocations\n", static_cast<unsigned long long>(record_allocs));

    // Export is the tool path, not the hot path; its cost scales with resident samples and is reported so a
    // capacity change can predict it.
    const std::uint64_t live_before_export = dmk_alloc::live_bytes();
    dmk_alloc::reset_peak();
    const std::string exported = profiler.export_chrome_json();
    const std::uint64_t export_peak = dmk_alloc::peak_live_bytes() - live_before_export;
    const double export_bytes_per_sample = static_cast<double>(export_peak) / static_cast<double>(profiler.capacity());
    std::printf("  export_chrome_json high-water: %llu bytes (%.1f bytes/resident sample, JSON %zu bytes)\n",
                static_cast<unsigned long long>(export_peak), export_bytes_per_sample, exported.size());

    const ProcessMemory os_final = process_memory(gates, "footprint.process_counters_stable");
    std::printf("\n  process private commit now: %llu bytes (%.1f MiB)\n",
                static_cast<unsigned long long>(os_final.private_bytes),
                static_cast<double>(os_final.private_bytes) / (1024.0 * 1024.0));

    std::printf("\n#TSV\tmetric\tvalue\n");
    std::printf("#TSV\tlog_message_slot_bytes\t%zu\n", sizeof(detail::LogMessage));
    std::printf("#TSV\tlogger_init_heap_bytes\t%llu\n", static_cast<unsigned long long>(logger_init_bytes));
    std::printf("#TSV\tlogger_init_private_bytes\t%llu\n", static_cast<unsigned long long>(logger_private_bytes));
    std::printf("#TSV\tlogger_allocs_per_inline_message\t%.4f\n", allocs_per_inline);
    std::printf("#TSV\tlogger_overflow_high_water_bytes\t%llu\n", static_cast<unsigned long long>(long_peak));
    std::printf("#TSV\tlogger_overflow_retained_bytes\t%llu\n", static_cast<unsigned long long>(long_retained));
    std::printf("#TSV\tlogger_retained_after_shutdown_bytes\t%llu\n", static_cast<unsigned long long>(logger_retained));
    std::printf("#TSV\tprofiler_ring_bytes\t%llu\n", static_cast<unsigned long long>(profiler_bytes));
    std::printf("#TSV\tprofiler_sample_bytes\t%zu\n", sizeof(detail::ProfileSample));
    std::printf("#TSV\tprofiler_export_high_water_bytes\t%llu\n", static_cast<unsigned long long>(export_peak));

    gates.metric("footprint.logger_init_heap_bytes", static_cast<double>(logger_init_bytes));
    gates.metric("footprint.logger_init_private_bytes", static_cast<double>(logger_private_bytes));
    gates.metric("footprint.logger_allocs_per_inline_message", allocs_per_inline);
    gates.metric("footprint.logger_overflow_high_water_bytes", static_cast<double>(long_peak));
    gates.metric("footprint.logger_retained_after_shutdown_bytes", static_cast<double>(logger_retained));
    gates.metric("footprint.profiler_ring_bytes", static_cast<double>(profiler_bytes));
    gates.metric("footprint.profiler_export_high_water_bytes", static_cast<double>(export_peak));
    return gates.close();
}
