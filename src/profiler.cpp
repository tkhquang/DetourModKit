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
#include <string_view>

namespace DetourModKit
{
    namespace
    {
        /**
         * @brief Escapes a string for safe embedding in a JSON value.
         * @details Handles the characters that are special in JSON strings:
         *          backslash, double quote, and control characters (U+0000..U+001F). Forward slash is NOT escaped
         *          (legal unescaped in JSON per RFC 8259).
         * @param input The raw string to escape.
         * @return A JSON-safe escaped string (without surrounding quotes).
         */
        std::string escape_json_string(std::string_view input)
        {
            std::string out;
            out.reserve(input.size());
            for (const char c : input)
            {
                switch (c)
                {
                case '"':
                    out += "\\\"";
                    break;
                case '\\':
                    out += "\\\\";
                    break;
                case '\b':
                    out += "\\b";
                    break;
                case '\f':
                    out += "\\f";
                    break;
                case '\n':
                    out += "\\n";
                    break;
                case '\r':
                    out += "\\r";
                    break;
                case '\t':
                    out += "\\t";
                    break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20)
                    {
                        // Control characters U+0000..U+001F require \uXXXX encoding
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x",
                                      static_cast<unsigned int>(static_cast<unsigned char>(c)));
                        out += buf;
                    }
                    else
                    {
                        out += c;
                    }
                    break;
                }
            }
            return out;
        }
    } // anonymous namespace

    // --- Profiler ---

    Profiler::Profiler()
        : m_buffer(std::make_unique<ProfileSample[]>(DEFAULT_CAPACITY)), m_capacity(DEFAULT_CAPACITY),
          m_mask(DEFAULT_CAPACITY - 1)
    {
        LARGE_INTEGER freq;
        // QueryPerformanceFrequency cannot fail and is always non-zero on Windows XP and later, but guard regardless: a
        // zero frequency would divide-by-zero in record(). Fall back to a 10 MHz tick so durations stay finite if the
        // API ever misbehaves.
        if (QueryPerformanceFrequency(&freq) && freq.QuadPart > 0)
        {
            m_qpc_frequency = freq.QuadPart;
        }
        else
        {
            m_qpc_frequency = 10'000'000;
        }
    }

    Profiler &Profiler::get_instance() noexcept
    {
        static Profiler instance;
        return instance;
    }

    void Profiler::record(const char *name, int64_t start_ticks, int64_t end_ticks, uint32_t thread_id) noexcept
    {
        // Clamp a non-positive delta (end before start: swapped arguments or a backwards clock read) to zero so the
        // unsigned cast below cannot wrap a negative value into a bogus multi-minute duration.
        const int64_t delta_ticks = end_ticks > start_ticks ? end_ticks - start_ticks : 0;

        // Convert ticks to microseconds: (delta * 1'000'000) / frequency. The 64-bit intermediate (delta * 1'000'000)
        // cannot overflow for any realistic
        // delta: at a 10 MHz QPC frequency it would take a delta over ~922,000 seconds.
        // duration_us is additionally clamped to UINT32_MAX microseconds (~71 minutes).
        const auto duration_us = static_cast<uint32_t>(
            std::min<int64_t>((delta_ticks * 1'000'000) / m_qpc_frequency, static_cast<int64_t>(UINT32_MAX)));

        const size_t idx = m_write_pos.fetch_add(1, std::memory_order_relaxed) & m_mask;

        auto &sample = m_buffer[idx];

        // Open the write window with a monotonic increment. The result is guaranteed odd because every closed sequence
        // is even (sequence starts at 0 in the constructor and reset(), and each record() contributes exactly +2).
        // Using fetch_add avoids the load-then-store RMW pattern: a producer preempted between a relaxed load and its
        // first store could otherwise roll the slot's sequence backwards if another producer completed a full write on
        // the same slot in the interim. fetch_add forbids that rollback.
        //
        // Design note: if a writer is stalled between its fetch_add and its final sequence store, and 65536 intervening
        // record() calls advance m_write_pos past a full buffer wrap, a new writer will land on the same slot and
        // clobber the stalled writer's data. This requires the stalled writer to be preempted for the duration of an
        // entire ring buffer cycle, which is unreachable at game-modding thread counts and frame rates. We accept this
        // theoretical imprecision to keep the hot path to a single fetch_add + two stores with no CAS retry loop.
        //
        // Monotonicity is unconditionally guaranteed by fetch_add: per
        // [atomics.types.operations] the counter cannot roll backwards regardless of how many producers race on the
        // same slot. Do NOT replace this with a load-then-store RMW: that would re-introduce the stale-publish race on
        // wrap collision that this protocol exists to prevent.
        static_assert(std::atomic<uint32_t>::is_always_lock_free,
                      "sequence counter must be lock-free for the seqlock protocol");
        (void)sample.sequence.fetch_add(1, std::memory_order_acq_rel);

        sample.name = name;
        sample.start_ticks = start_ticks;
        sample.duration_us = duration_us;
        sample.thread_id = thread_id;

        // Close the write window. Another +1 keeps the slot's sequence monotonic and lands it on an even value,
        // signalling a fully committed sample. Readers that observe an odd value skip this slot to avoid reading torn
        // fields.
        (void)sample.sequence.fetch_add(1, std::memory_order_release);
    }

    // Caller must ensure no concurrent record() calls are in flight. There is no runtime guard because adding an atomic
    // "recording active" counter would penalize every record() call on the hot path for a contract that is only
    // relevant during session boundaries.
    void Profiler::reset() noexcept
    {
        m_write_pos.store(0, std::memory_order_relaxed);
        for (size_t i = 0; i < m_capacity; ++i)
        {
            auto &sample = m_buffer[i];
            sample.sequence.store(0, std::memory_order_relaxed);
            sample.name = nullptr;
            sample.start_ticks = 0;
            sample.duration_us = 0;
            sample.thread_id = 0;
        }
    }

    std::string Profiler::export_chrome_json() const
    {
        const size_t total = m_write_pos.load(std::memory_order_relaxed);
        const size_t count = std::min(total, m_capacity);

        if (count == 0)
        {
            return "[]";
        }

        // Determine start index: if the buffer has wrapped, start from the oldest surviving sample; otherwise start
        // from 0.
        const size_t start_idx = (total > m_capacity) ? (total & m_mask) : 0;

        // Pre-allocate: ~120 bytes per JSON event is a reasonable estimate.
        std::string json;
        json.reserve(count * 120 + 4);
        json += "[\n";

        // QPC frequency for converting start_ticks to microseconds
        const double ticks_to_us = 1'000'000.0 / static_cast<double>(m_qpc_frequency);

        bool first = true;
        for (size_t i = 0; i < count; ++i)
        {
            const auto &sample = m_buffer[(start_idx + i) & m_mask];

            // Seqlock read: load the sequence, copy the sample fields into locals, then re-load the sequence. record()
            // opens a write with an odd sequence and closes it with the next even value, so a sample is consistent only
            // when the pre-read sequence is even (no in-flight write) AND the post-read sequence is unchanged (no write
            // started and finished mid-copy). The acquire fence between the field copies and the second load stops the
            // copies from being reordered after it. This runs on the cold export path; the second load costs nothing
            // measurable and the producer hot path is untouched.
            const uint32_t seq_before = sample.sequence.load(std::memory_order_acquire);
            if ((seq_before & 1) != 0 || sample.name == nullptr)
            {
                continue;
            }

            const char *name = sample.name;
            const auto start_ticks = sample.start_ticks;
            const auto duration_us = sample.duration_us;
            const auto thread_id = sample.thread_id;

            std::atomic_thread_fence(std::memory_order_acquire);
            const uint32_t seq_after = sample.sequence.load(std::memory_order_relaxed);
            if (seq_after != seq_before)
            {
                // A producer overwrote this slot mid-copy; drop the torn sample.
                continue;
            }

            if (!first)
            {
                json += ",\n";
            }
            first = false;

            // Chrome Trace Event Format: "X" = complete event (has duration). Escape the name to produce valid JSON
            // even if the caller passes a string containing quotes or backslashes.
            const double ts = static_cast<double>(start_ticks) * ticks_to_us;
            const std::string escaped_name = escape_json_string(name);
            json += std::format(R"({{"name":"{}","ph":"X","ts":{:.1f},"dur":{},"pid":1,"tid":{}}})", escaped_name, ts,
                                duration_us, thread_id);
        }

        json += "\n]";
        return json;
    }

    bool Profiler::export_to_file(std::string_view path) const
    {
        const std::string json = export_chrome_json();
        const std::string path_str(path);

        const auto closer = [](std::FILE *f) { std::fclose(f); };
        std::FILE *file_ptr = nullptr;

        const errno_t err = fopen_s(&file_ptr, path_str.c_str(), "wb");
        if (err != 0 || file_ptr == nullptr)
        {
            return false;
        }

        std::unique_ptr<std::FILE, decltype(closer)> fp(file_ptr, closer);
        const size_t written = std::fwrite(json.data(), 1, json.size(), fp.get());
        if (written != json.size())
        {
            return false;
        }
        if (std::fflush(fp.get()) != 0)
        {
            return false;
        }
        // Release the pointer so unique_ptr does not double-close.
        if (std::fclose(fp.release()) != 0)
        {
            return false;
        }
        return true;
    }

    size_t Profiler::total_samples_recorded() const noexcept
    {
        return m_write_pos.load(std::memory_order_relaxed);
    }

    size_t Profiler::available_samples() const noexcept
    {
        return std::min(m_write_pos.load(std::memory_order_relaxed), m_capacity);
    }

    size_t Profiler::capacity() const noexcept
    {
        return m_capacity;
    }

    int64_t Profiler::qpc_frequency() const noexcept
    {
        return m_qpc_frequency;
    }

    // --- ScopedProfile ---

    ScopedProfile::ScopedProfile(const char *name, literal_tag) noexcept
        : m_name(name), m_thread_id(GetCurrentThreadId())
    {
        LARGE_INTEGER ticks;
        QueryPerformanceCounter(&ticks);
        m_start_ticks = ticks.QuadPart;
    }

    ScopedProfile::~ScopedProfile() noexcept
    {
        LARGE_INTEGER ticks;
        QueryPerformanceCounter(&ticks);
        Profiler::get_instance().record(m_name, m_start_ticks, ticks.QuadPart, m_thread_id);
    }

} // namespace DetourModKit
