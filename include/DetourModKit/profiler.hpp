#ifndef DETOURMODKIT_PROFILER_HPP
#define DETOURMODKIT_PROFILER_HPP

/**
 * @file profiler.hpp
 * @brief Opt-in profiling instrumentation for measuring hook and subsystem timing.
 *
 * @details Provides zero-overhead profiling when disabled at compile time.
 *          When enabled via DMK_ENABLE_PROFILING, records scoped timing samples
 *          into a lock-free ring buffer and exports to Chrome Tracing JSON format
 *          (viewable in chrome://tracing or https://ui.perfetto.dev).
 *
 *          **Compile-time control:**
 *          - Define DMK_ENABLE_PROFILING before including this header, or
 *          - Pass -DDMK_ENABLE_PROFILING=ON to CMake.
 *
 *          **Performance characteristics (when enabled):**
 *          - ~50 ns per scoped measurement (two QPC calls + one atomic store)
 *          - Fixed-size ring buffer (no heap allocations on the hot path)
 *          - Lock-free recording from multiple threads
 *
 *          **Usage:**
 *          @code
 *          void on_camera_update(void* camera_ptr) {
 *              DMK_PROFILE_SCOPE("camera_update");
 *              // ... hook logic ...
 *          }
 *
 *          // Export after a profiling session
 *          DMKProfiler::get_instance().export_to_file("profile.json");
 *          @endcode
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#ifdef DMK_ENABLE_PROFILING

// Two-level indirection so __LINE__ expands before token pasting.
#define DMK_CONCAT_IMPL(a, b) a##b
#define DMK_CONCAT(a, b) DMK_CONCAT_IMPL(a, b)

// Scoped timing measurement. Name must be a string literal.
#define DMK_PROFILE_SCOPE(name) \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_, __LINE__) { name }

// Scoped timing using the enclosing function name.
#define DMK_PROFILE_FUNCTION() \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_func_, __LINE__) { __FUNCTION__ }

#else

#define DMK_PROFILE_SCOPE(name) ((void)0)
#define DMK_PROFILE_FUNCTION() ((void)0)

#endif // DMK_ENABLE_PROFILING

namespace DetourModKit
{
    /**
     * @brief A single timing sample recorded by the profiler.
     * @details The sequence field uses odd/even protocol to detect in-flight
     *          writes: record() stores an odd sequence before writing fields
     *          and an even sequence after. Readers skip samples with odd
     *          sequence values (torn/in-progress writes).
     */
    struct ProfileSample
    {
        std::atomic<uint32_t> sequence{0}; ///< Odd = write in progress, even = committed.
        const char *name{nullptr};         ///< Non-owning pointer; must have static storage duration.
        int64_t start_ticks{0};            ///< QPC tick count at scope entry.
        uint32_t duration_us{0};           ///< Duration in microseconds (max ~71 minutes).
        uint32_t thread_id{0};             ///< Win32 thread ID of the recording thread.

        ProfileSample() noexcept = default;
        ProfileSample(const ProfileSample &) = delete;
        ProfileSample &operator=(const ProfileSample &) = delete;
        ProfileSample(ProfileSample &&) = delete;
        ProfileSample &operator=(ProfileSample &&) = delete;
    };

    /**
     * @brief Lock-free ring buffer profiler with Chrome Tracing JSON export.
     *
     * @details Uses a fixed-capacity power-of-2 ring buffer. Recording is lock-free
     *          via a single atomic fetch_add on the write position. When the buffer
     *          wraps, oldest samples are silently overwritten (no allocation, no lock).
     *
     *          The profiler is a singleton. All public methods are safe to call from
     *          multiple threads. Export methods take a consistent snapshot by reading
     *          the current write position and walking backwards.
     *
     * **Thread safety:**
     * - `record()`: lock-free (atomic fetch_add + sequence counter)
     * - `reset()`: safe when no concurrent `record()` calls are in flight
     * - `export_chrome_json()` / `export_to_file()`: safe to call concurrently
     *   with `record()`. Uses odd/even sequence protocol to skip in-flight
     *   writes, preventing torn reads in the exported data
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

        /// Returns the global profiler singleton.
        [[nodiscard]] static Profiler &get_instance() noexcept;

        /**
         * @brief Records a completed timing sample.
         * @param name Non-owning pointer that must have static storage duration
         *        (e.g. a string literal). The pointer is stored as-is in the
         *        ring buffer and read asynchronously by export methods. Passing
         *        a pointer to a temporary (e.g. std::string::c_str()) causes
         *        undefined behavior. The DMK_PROFILE_SCOPE() macro forwards its
         *        argument directly to ScopedProfile and does not enforce static
         *        storage at compile time; callers should pass string literals
         *        or ensure the pointed-to string outlives the profiler.
         * @param start_ticks QPC tick count at scope entry.
         * @param end_ticks QPC tick count at scope exit.
         * @param thread_id Win32 thread ID of the recording thread.
         * @note Lock-free. Safe to call from any thread at any time.
         */
        void record(const char *name, int64_t start_ticks, int64_t end_ticks,
                    uint32_t thread_id) noexcept;

        /**
         * @brief Resets the profiler, discarding all recorded samples.
         * @note Not safe to call while other threads are calling record().
         *       Intended for use between profiling sessions.
         */
        void reset() noexcept;

        /**
         * @brief Exports recorded samples as a Chrome Tracing JSON string.
         * @details Output conforms to the Chrome Trace Event Format (array form).
         *          Open the result in chrome://tracing or https://ui.perfetto.dev.
         * @return JSON string containing all recorded samples.
         */
        [[nodiscard]] std::string export_chrome_json() const;

        /**
         * @brief Exports recorded samples to a JSON file on disk.
         * @param path File path to write (created or overwritten).
         * @return true on success, false on I/O failure.
         */
        [[nodiscard]] bool export_to_file(std::string_view path) const;

        /// Returns the number of samples recorded (may exceed capacity due to wrapping).
        [[nodiscard]] size_t total_samples_recorded() const noexcept;

        /// Returns the number of valid samples available for export (min of recorded, capacity).
        [[nodiscard]] size_t available_samples() const noexcept;

        /// Returns the ring buffer capacity.
        [[nodiscard]] size_t capacity() const noexcept;

        /// Returns the QPC frequency (ticks per second) used for timing.
        [[nodiscard]] int64_t qpc_frequency() const noexcept;

    private:
        Profiler();
        ~Profiler() = default;

        // write_pos_ first to avoid 40 bytes of padding (alignas(64) requirement).
        // This placement ensures cache-line alignment for the lock-free ring buffer.
        alignas(64) std::atomic<size_t> write_pos_{0};
        std::unique_ptr<ProfileSample[]> buffer_;
        size_t capacity_;
        size_t mask_; // capacity_ - 1 for power-of-2 index wrapping
        int64_t qpc_frequency_{0};
    };

    /**
     * @brief RAII scoped profiler that records timing on destruction.
     *
     * @details Captures QPC tick count and thread ID in the constructor.
     *          On destruction, computes duration and records the sample in the
     *          global Profiler ring buffer.
     *
     *          This class is only active when DMK_ENABLE_PROFILING is defined.
     *          Use the DMK_PROFILE_SCOPE() macro instead of constructing directly.
     */
    class ScopedProfile
    {
    public:
        /**
         * @brief Begins a profiling scope.
         * @param name Non-owning pointer to a string literal. Must outlive this object.
         */
        explicit ScopedProfile(const char *name) noexcept;
        ~ScopedProfile() noexcept;

        ScopedProfile(const ScopedProfile &) = delete;
        ScopedProfile &operator=(const ScopedProfile &) = delete;
        ScopedProfile(ScopedProfile &&) = delete;
        ScopedProfile &operator=(ScopedProfile &&) = delete;

    private:
        const char *name_;
        int64_t start_ticks_;
        uint32_t thread_id_;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_PROFILER_HPP
