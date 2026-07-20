/**
 * @file profiler.cpp
 * @brief Implementation of the lock-free ring buffer profiler with Chrome Tracing export.
 */

#include "DetourModKit/profiler.hpp"

#include <windows.h>
#include <cstdio>
#include <format>
#include <memory>
#include <new>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace
    {
        /**
         * @brief Escapes a string for safe embedding in a JSON value.
         * @details Escapes backslash, double quote, and the control characters U+0000..U+001F. Forward slash is left
         *          alone (legal unescaped per RFC 8259).
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
    } // namespace

    Profiler::Profiler() noexcept : m_ring(DEFAULT_CAPACITY)
    {
        LARGE_INTEGER freq;
        // QueryPerformanceFrequency cannot fail and is always non-zero on Windows XP and later, but guard regardless: a
        // zero frequency would make every conversion degenerate. Fall back to a 10 MHz tick so durations stay finite if
        // the API ever misbehaves.
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
        // Constructed once into function-local static storage and never destroyed, mirroring StringPool::instance().
        // A Meyers singleton (`static Profiler instance;`) registers a static destructor that frees the ring at
        // static-teardown time. A ScopedProfile whose own destructor runs after that -- a static or thread_local
        // ScopedProfile, or one on a thread still alive at process teardown -- would then record through this accessor
        // into freed storage. Placement-new into raw static storage keeps the object alive for the whole process; the
        // single fixed-size ring is reclaimed by the OS at exit.
        //
        // Construction cannot throw: the ring allocates with nothrow new and reports capacity 0 if that fails, so the
        // worst first-use outcome is a disabled profiler rather than a terminate out of this noexcept accessor.
        alignas(Profiler) static unsigned char storage[sizeof(Profiler)];
        static Profiler *const instance = ::new (static_cast<void *>(storage)) Profiler();
        return *instance;
    }

    void Profiler::record(const char *name, int64_t start_ticks, int64_t end_ticks, uint32_t thread_id) noexcept
    {
        const auto claim = m_ring.claim();
        if (!claim.owned)
        {
            return;
        }
        m_ring.publish(claim, name, start_ticks, detail::ticks_to_microseconds(start_ticks, end_ticks, m_qpc_frequency),
                       thread_id);
    }

    // Caller must ensure no concurrent record() calls are in flight. There is no runtime guard because an atomic
    // "recording active" counter would penalize every record() call on the hot path for a contract that only matters at
    // session boundaries.
    void Profiler::reset() noexcept
    {
        m_ring.reset();
    }

    std::string Profiler::export_chrome_json() const
    {
        std::string json;
        const auto resident = static_cast<size_t>(m_ring.resident());
        if (resident == 0)
        {
            return "[]";
        }

        // ~120 bytes per JSON event is a reasonable estimate.
        json.reserve(resident * 120 + 4);
        json += "[\n";

        const double ticks_to_us = 1'000'000.0 / static_cast<double>(m_qpc_frequency);
        bool first = true;
        m_ring.visit_committed(
            [&](const char *name, int64_t start_ticks, uint32_t duration_us, uint32_t thread_id)
            {
                if (!first)
                {
                    json += ",\n";
                }
                first = false;

                // Chrome Trace Event Format: "X" = complete event (has duration). The name is escaped so a caller's
                // quotes or backslashes still produce valid JSON.
                const double ts = static_cast<double>(start_ticks) * ticks_to_us;
                json += std::format(R"({{"name":"{}","ph":"X","ts":{:.1f},"dur":{},"pid":1,"tid":{}}})",
                                    escape_json_string(name), ts, duration_us, thread_id);
            });

        if (first)
        {
            return "[]";
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
        return static_cast<size_t>(m_ring.claims());
    }

    size_t Profiler::available_samples() const noexcept
    {
        return static_cast<size_t>(m_ring.resident());
    }

    size_t Profiler::dropped_samples() const noexcept
    {
        return static_cast<size_t>(m_ring.dropped());
    }

    size_t Profiler::capacity() const noexcept
    {
        return m_ring.capacity();
    }

    int64_t Profiler::qpc_frequency() const noexcept
    {
        return m_qpc_frequency;
    }

    ScopedProfile::ScopedProfile(const char *name, LiteralTag) noexcept
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
