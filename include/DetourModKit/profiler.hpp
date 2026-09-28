#ifndef DETOURMODKIT_PROFILER_HPP
#define DETOURMODKIT_PROFILER_HPP

/**
 * @file profiler.hpp
 * @brief Opt-in timing instrumentation with a lock-free ring and Chrome Tracing JSON export.
 * @details DMK_PROFILE_SCOPE and DMK_PROFILE_FUNCTION expand to a no-op unless DMK_ENABLE_PROFILING is defined. The
 *          CMake option DMK_ENABLE_PROFILING=ON defines it for every target that links DetourModKit.
 * @warning `[B-100]` Run first use of Profiler::get_instance() and the export routes outside the loader lock. First
 *          use allocates the ring. The export routes can allocate, and export_to_file() writes a file. A warm record()
 *          is allocation-free from any thread. `ProfilerLoaderBoundary.*` pins the boundary.
 */

#include "DetourModKit/detail/profile_ring.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#ifdef DMK_ENABLE_PROFILING

// Two-level indirection so __LINE__ expands before token pasting.
#define DMK_CONCAT_IMPL(a, b) a##b
#define DMK_CONCAT(a, b) DMK_CONCAT_IMPL(a, b)

// Scoped timer. ScopedProfile owns the label lifetime and extent contract for `name`.
#define DMK_PROFILE_SCOPE(name)                                                                                        \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_, __LINE__)                                            \
    {                                                                                                                  \
        name                                                                                                           \
    }

// Scoped timer for the current function. `__func__` has static storage per [dcl.fct.def.general]/8.
#define DMK_PROFILE_FUNCTION()                                                                                         \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_func_, __LINE__)                                       \
    {                                                                                                                  \
        __func__                                                                                                       \
    }

#else

#define DMK_PROFILE_SCOPE(name) ((void)0)
#define DMK_PROFILE_FUNCTION() ((void)0)

#endif // DMK_ENABLE_PROFILING

namespace DetourModKit
{
    /**
     * @brief Lock-free ring buffer profiler with Chrome Tracing JSON export.
     * @details Each record() call claims one slot of a fixed ring, and new samples overwrite the oldest. A claim on a
     *          slot that another writer still owns is refused, so export never sees a torn sample. Export is safe
     *          concurrently with record(). The instance is never destroyed, so a ScopedProfile that outlives static
     *          teardown still records safely. Each linked DMK instance has its own profiler.
     */
    class Profiler
    {
    public:
        /// Default ring buffer capacity, a power of two.
        static constexpr size_t DEFAULT_CAPACITY{65536};

        Profiler(const Profiler &) = delete;
        Profiler &operator=(const Profiler &) = delete;
        Profiler(Profiler &&) = delete;
        Profiler &operator=(Profiler &&) = delete;

        /**
         * @brief Returns the profiler singleton.
         * @details If first use cannot allocate the ring, it publishes a disabled profiler for the life of this DMK
         *          instance. A disabled profiler exports an empty trace and resets safely. First use never terminates.
         */
        [[nodiscard]] static Profiler &get_instance() noexcept;

        /**
         * @brief Records a completed profile sample whose label is null-terminated.
         * @param name A label that export reads later. Its storage must stay readable until process exit, or the
         *             behavior is undefined. A non-null @p name must be null-terminated. A null @p name records a
         *             sample that export skips. @ref ScopedProfile lists safe label sources.
         * @param start_ticks QPC tick count at scope entry.
         * @param end_ticks QPC tick count at scope exit. An interval with `end_ticks <= start_ticks` records zero. A
         *                  long interval saturates and never overflows.
         * @param thread_id Win32 thread ID of the source thread.
         * @note Lock-free, with no allocation or system call. Safe to call from any thread, but not during reset().
         */
        void record(const char *name, int64_t start_ticks, int64_t end_ticks, uint32_t thread_id) noexcept;

        /**
         * @brief Records a completed profile sample whose label extent the caller supplies. The other parameters
         *        follow the null-terminated overload.
         * @param name If @p name is not null, @p name_length bytes must stay readable until process exit. No terminator
         *             is required. A null @p name records a sample that export skips.
         * @param name_length Export reads exactly this many bytes. A value above `UINT32_MAX` saturates.
         * @note Lock-free, with no allocation or system call. Safe to call from any thread, but not during reset().
         */
        void record(
            const char *name,
            size_t name_length,
            int64_t start_ticks,
            int64_t end_ticks,
            uint32_t thread_id
        ) noexcept;

        /** @brief Discards all samples and counters. If a record() call is in flight, do not call it. */
        void reset() noexcept;

        /** @brief Exports the resident samples as a Chrome Tracing JSON array, or "[]" if none are resident. */
        [[nodiscard]] std::string export_chrome_json() const;

        /**
         * @brief Writes the Chrome Tracing JSON to the UTF-8 @p path, which it creates or overwrites.
         * @return true on success, or false on ill-formed UTF-8, an embedded NUL, or an I/O failure.
         */
        [[nodiscard]] bool export_to_file(std::string_view path) const;

        /// Returns the number of record() calls. The count can exceed the capacity after the ring wraps.
        [[nodiscard]] size_t total_samples_recorded() const noexcept;

        /// Returns the number of resident samples. Export skips the null-label samples among them.
        [[nodiscard]] size_t available_samples() const noexcept;

        /// Returns the number of record() calls refused because the ring is disabled or another writer took their slot.
        [[nodiscard]] size_t dropped_samples() const noexcept;

        /// Returns the ring buffer capacity, or 0 for a disabled profiler.
        [[nodiscard]] size_t capacity() const noexcept;

        /// Returns the QPC frequency (ticks per second) used for timing.
        [[nodiscard]] int64_t qpc_frequency() const noexcept;

    private:
        Profiler() noexcept;
        ~Profiler() noexcept = default;

        detail::ProfileRing m_ring;
        int64_t m_qpc_frequency{0};
    };

    /**
     * @brief Captures the start tick and thread ID at construction and records one sample at destruction. The profiling
     *        macros create one only when DMK_ENABLE_PROFILING is defined, but direct construction always records.
     */
    class ScopedProfile
    {
    public:
        /**
         * @brief Begins a profiling scope.
         * @param name An array that must stay readable until process exit. An automatic array compiles but dangles.
         *             Safe sources are string literals, namespace-scope `static constexpr char` arrays, and `__func__`.
         * @details The label extent is `N` without one final null. An array with no terminator exports all its bytes.
         */
        template <size_t N>
        explicit ScopedProfile(const char (&name)[N]) noexcept
            : ScopedProfile(static_cast<const char *>(name), name[N - 1] == '\0' ? N - 1 : N, LiteralTag{})
        {
        }
        ~ScopedProfile() noexcept;

        ScopedProfile(const ScopedProfile &) = delete;
        ScopedProfile &operator=(const ScopedProfile &) = delete;
        ScopedProfile(ScopedProfile &&) = delete;
        ScopedProfile &operator=(ScopedProfile &&) = delete;

    private:
        struct LiteralTag
        {
        };

        ScopedProfile(const char *name, size_t name_length, LiteralTag) noexcept;

        const char *m_name;
        size_t m_name_length;
        int64_t m_start_ticks;
        uint32_t m_thread_id;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_PROFILER_HPP
