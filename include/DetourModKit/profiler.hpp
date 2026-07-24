#ifndef DETOURMODKIT_PROFILER_HPP
#define DETOURMODKIT_PROFILER_HPP

/**
 * @file profiler.hpp
 * @brief Opt-in profiling instrumentation for measuring hook and subsystem timing.
 *
 * @details Compiles to nothing unless DMK_ENABLE_PROFILING is defined (directly, or through -DDMK_ENABLE_PROFILING=ON).
 *          When enabled, scoped measurements land in a fixed-capacity lock-free ring and export as Chrome Tracing JSON
 *          (chrome://tracing, https://ui.perfetto.dev).
 *
 *          @code
 *          void on_camera_update(void* camera_ptr) {
 *              DMK_PROFILE_SCOPE("camera_update");
 *              // ... hook logic ...
 *          }
 *
 *          DetourModKit::Profiler::get_instance().export_to_file("profile.json");
 *          @endcode
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

// Scoped timing measurement. The `name` argument must refer to storage that outlives the process, because the pointer
// is stored unchanged in the ring buffer and read asynchronously by export methods. String literals satisfy this
// automatically.
//
// The ScopedProfile(const char (&)[N]) constructor rejects decayed `const char *` / `char *` sources (see
// static_asserts in test_profiler.cpp), but array-reference binding accepts any array, including function-local `char
// buf[N]`. Callers remain responsible for static-storage lifetime. Prefer string literals or namespace-scope `static
// constexpr char` arrays.
#define DMK_PROFILE_SCOPE(name)                                                                                        \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_, __LINE__)                                            \
    {                                                                                                                  \
        name                                                                                                           \
    }

// Scoped timing using the enclosing function name. `__func__` is a static-storage array per [dcl.fct.def.general]/8, so
// it binds to the array-reference constructor and the stored pointer remains valid for the lifetime of the process.
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
     *
     * @details Recording claims one slot of a fixed power-of-two ring and publishes into it; when the ring wraps, the
     *          oldest samples are overwritten. A claim that would collide with a slot another writer still owns is
     *          refused and counted by @ref dropped_samples rather than overwriting it, so the exporter never observes a
     *          torn sample. No allocation, lock, or system call occurs on the recording path.
     *
     *          The instance is process-lifetime and is never destroyed, so a ScopedProfile that outlives ordinary
     *          static teardown still records safely. It is per linked DMK instance, not per process: two modules that
     *          each link the static library each get their own profiler.
     *
     * **Thread safety:**
     * - `record()`: lock-free, callable from any thread
     * - `reset()`: safe only when no `record()` call is in flight
     * - `export_chrome_json()` / `export_to_file()`: safe concurrently with `record()`
     */
    class Profiler
    {
    public:
        /// Default ring buffer capacity (must be a power of 2).
        static constexpr size_t DEFAULT_CAPACITY{65536};

        Profiler(const Profiler &) = delete;
        Profiler &operator=(const Profiler &) = delete;
        Profiler(Profiler &&) = delete;
        Profiler &operator=(Profiler &&) = delete;

        /**
         * @brief Returns the profiler singleton.
         * @details First use publishes either a complete profiler or, if its ring cannot be allocated, a disabled one
         *          whose @ref capacity is 0. Recording then fails closed and increments @ref dropped_samples, export
         *          returns an empty trace, and reset remains safe. It never terminates or publishes a partially
         *          constructed profiler; a first-use failure latches for the lifetime of this linked instance.
         */
        [[nodiscard]] static Profiler &get_instance() noexcept;

        /**
         * @brief Records a completed timing sample.
         * @param name Non-owning pointer that must outlive the process. The pointer is stored as-is in the ring buffer
         *             and read asynchronously by export methods. Passing a pointer whose storage is released before
         *             process exit (std::string::c_str(), heap buffers, function-local arrays) is undefined behavior.
         *             Neither this entry point nor the ScopedProfile(const char (&)[N]) constructor enforces
         *             static-storage at compile time; array-reference binding accepts any array, so callers remain
         *             responsible for lifetime. Safe sources: string literals, `static constexpr char` arrays at
         *             namespace scope, and `__func__` (see [dcl.fct.def.general]/8).
         * @param start_ticks QPC tick count at scope entry.
         * @param end_ticks QPC tick count at scope exit. Any ordering and any magnitude is accepted: a non-increasing
         *                  interval records a zero duration and a long one saturates, neither overflows.
         * @param thread_id Win32 thread ID of the recording thread.
         * @note Lock-free. Safe to call from any thread at any time.
         */
        void record(const char *name, int64_t start_ticks, int64_t end_ticks, uint32_t thread_id) noexcept;

        /**
         * @brief Resets the profiler, discarding all recorded samples and counters.
         * @note Not safe to call while other threads are calling record(). Intended for use between profiling sessions.
         */
        void reset() noexcept;

        /**
         * @brief Exports recorded samples as a Chrome Tracing JSON string (array form).
         * @return JSON string containing all recorded samples, or "[]" when none are resident.
         */
        [[nodiscard]] std::string export_chrome_json() const;

        /**
         * @brief Exports recorded samples to a JSON file on disk.
         * @param path File path to write (created or overwritten).
         * @return true on success, false on I/O failure.
         */
        [[nodiscard]] bool export_to_file(std::string_view path) const;

        /// Returns the number of record() calls made (may exceed capacity due to wrapping).
        [[nodiscard]] size_t total_samples_recorded() const noexcept;

        /// Returns the number of committed samples available for export.
        [[nodiscard]] size_t available_samples() const noexcept;

        /// Returns the number of record() calls refused because their slot was still owned, or the ring is disabled.
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
     * @brief RAII scoped profiler that records timing on destruction.
     *
     * @details Captures the QPC tick count and thread ID on construction and records the completed sample on
     *          destruction. The profiling macros instantiate this class only when DMK_ENABLE_PROFILING is defined;
     *          direct construction always records and is intended for specialized instrumentation.
     */
    class ScopedProfile
    {
    public:
        /**
         * @brief Begins a profiling scope.
         * @tparam N Deduced length of the bound array (including the trailing null terminator when the source is a
         *           string literal).
         * @param name Reference to a `const char` array. The array-reference parameter rejects decayed pointer sources
         *        (`std::string::c_str()`, `const char *` function arguments, `char *` buffers) at compile time.
         *        Reference binding still accepts an array with automatic storage, which dangles once its scope exits,
         *        so this does NOT prove static storage; callers must ensure the bound array outlives the process. Safe
         *        sources: string literals, namespace-scope `static constexpr char` arrays, and `__func__`
         *        (static-storage per [dcl.fct.def.general]/8).
         */
        template <size_t N>
        explicit ScopedProfile(const char (&name)[N]) noexcept
            : ScopedProfile(static_cast<const char *>(name), LiteralTag{})
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

        ScopedProfile(const char *name, LiteralTag) noexcept;

        const char *m_name;
        int64_t m_start_ticks;
        uint32_t m_thread_id;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_PROFILER_HPP
