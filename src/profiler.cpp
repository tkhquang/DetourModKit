/**
 * @file profiler.cpp
 * @brief Implementation of the lock-free ring buffer profiler with Chrome Tracing export.
 */

#include "DetourModKit/profiler.hpp"

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <format>
#include <memory>
#include <string>

namespace DetourModKit
{
    // --- Profiler ---

    Profiler::Profiler()
        : buffer_(std::make_unique<ProfileSample[]>(DEFAULT_CAPACITY)),
          capacity_(DEFAULT_CAPACITY),
          mask_(DEFAULT_CAPACITY - 1)
    {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        qpc_frequency_ = freq.QuadPart;
    }

    Profiler &Profiler::get_instance() noexcept
    {
        static Profiler instance;
        return instance;
    }

    void Profiler::record(const char *name, int64_t start_ticks, int64_t end_ticks,
                          uint32_t thread_id) noexcept
    {
        const int64_t delta_ticks = end_ticks - start_ticks;

        // Convert ticks to microseconds: (delta * 1'000'000) / frequency.
        // Use 64-bit intermediate to avoid overflow for deltas up to ~9200 seconds
        // at a 10 MHz QPC frequency (common on modern hardware).
        const auto duration_us = static_cast<uint32_t>(
            std::min<int64_t>((delta_ticks * 1'000'000) / qpc_frequency_,
                              static_cast<int64_t>(UINT32_MAX)));

        const size_t idx = write_pos_.fetch_add(1, std::memory_order_relaxed) & mask_;

        auto &sample = buffer_[idx];

        // Odd sequence signals an in-progress write. Readers that observe
        // an odd value skip this sample to avoid reading torn fields.
        const uint32_t seq = sample.sequence.load(std::memory_order_relaxed);
        sample.sequence.store(seq | 1, std::memory_order_release);

        sample.name = name;
        sample.start_ticks = start_ticks;
        sample.duration_us = duration_us;
        sample.thread_id = thread_id;

        // Even sequence signals the write is complete and fields are consistent.
        sample.sequence.store((seq | 1) + 1, std::memory_order_release);
    }

    // Caller must ensure no concurrent record() calls are in flight.
    // There is no runtime guard because adding an atomic "recording active"
    // counter would penalize every record() call on the hot path for a
    // contract that is only relevant during session boundaries.
    void Profiler::reset() noexcept
    {
        write_pos_.store(0, std::memory_order_relaxed);
        for (size_t i = 0; i < capacity_; ++i)
        {
            auto &s = buffer_[i];
            s.sequence.store(0, std::memory_order_relaxed);
            s.name = nullptr;
            s.start_ticks = 0;
            s.duration_us = 0;
            s.thread_id = 0;
        }
    }

    std::string Profiler::export_chrome_json() const
    {
        const size_t total = write_pos_.load(std::memory_order_relaxed);
        const size_t count = std::min(total, capacity_);

        if (count == 0)
        {
            return "[]";
        }

        // Determine start index: if the buffer has wrapped, start from the
        // oldest surviving sample; otherwise start from 0.
        const size_t start_idx = (total > capacity_) ? (total & mask_) : 0;

        // Pre-allocate: ~120 bytes per JSON event is a reasonable estimate.
        std::string json;
        json.reserve(count * 120 + 4);
        json += "[\n";

        // QPC frequency for converting start_ticks to microseconds
        const double ticks_to_us = 1'000'000.0 / static_cast<double>(qpc_frequency_);

        bool first = true;
        for (size_t i = 0; i < count; ++i)
        {
            const auto &s = buffer_[(start_idx + i) & mask_];

            // Skip samples with odd sequence (in-flight write) or null name.
            const uint32_t seq = s.sequence.load(std::memory_order_acquire);
            if ((seq & 1) != 0 || s.name == nullptr)
            {
                continue;
            }

            if (!first)
            {
                json += ",\n";
            }
            first = false;

            // Chrome Trace Event Format: "X" = complete event (has duration)
            const double ts = static_cast<double>(s.start_ticks) * ticks_to_us;
            json += std::format(
                R"({{"name":"{}","ph":"X","ts":{:.1f},"dur":{},"pid":1,"tid":{}}})",
                s.name, ts, s.duration_us, s.thread_id);
        }

        json += "\n]";
        return json;
    }

    bool Profiler::export_to_file(std::string_view path) const
    {
        const std::string json = export_chrome_json();
        const std::string path_str(path);

        const auto closer = [](std::FILE *f) { std::fclose(f); };
        std::unique_ptr<std::FILE, decltype(closer)> fp(
            std::fopen(path_str.c_str(), "wb"), closer);
        if (!fp)
        {
            return false;
        }
        const size_t written = std::fwrite(json.data(), 1, json.size(), fp.get());
        return written == json.size();
    }

    size_t Profiler::total_samples_recorded() const noexcept
    {
        return write_pos_.load(std::memory_order_relaxed);
    }

    size_t Profiler::available_samples() const noexcept
    {
        return std::min(write_pos_.load(std::memory_order_relaxed), capacity_);
    }

    size_t Profiler::capacity() const noexcept
    {
        return capacity_;
    }

    int64_t Profiler::qpc_frequency() const noexcept
    {
        return qpc_frequency_;
    }

    // --- ScopedProfile ---

    ScopedProfile::ScopedProfile(const char *name) noexcept
        : name_(name), thread_id_(GetCurrentThreadId())
    {
        LARGE_INTEGER ticks;
        QueryPerformanceCounter(&ticks);
        start_ticks_ = ticks.QuadPart;
    }

    ScopedProfile::~ScopedProfile() noexcept
    {
        LARGE_INTEGER ticks;
        QueryPerformanceCounter(&ticks);
        Profiler::get_instance().record(name_, start_ticks_, ticks.QuadPart, thread_id_);
    }

} // namespace DetourModKit
