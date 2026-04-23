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

// Scoped timing measurement. The `name` argument must refer to storage that
// outlives the process, because the pointer is stored unchanged in the ring
// buffer and read asynchronously by export methods. String literals satisfy
// this automatically.
//
// The ScopedProfile(const char (&)[N]) constructor rejects decayed `const
// char *` / `char *` sources (see static_asserts in test_profiler.cpp), but
// array-reference binding accepts any array, including function-local
// `char buf[N]`. Callers remain responsible for static-storage lifetime.
// Prefer string literals or namespace-scope `static constexpr char` arrays.
#define DMK_PROFILE_SCOPE(name) \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_, __LINE__) { name }

// Scoped timing using the enclosing function name. `__func__` is a static-
// storage array per [dcl.fct.def.general]/8, so it binds to the array-
// reference constructor and the stored pointer remains valid for the
// lifetime of the process.
#define DMK_PROFILE_FUNCTION() \
    ::DetourModKit::ScopedProfile DMK_CONCAT(dmk_scoped_profile_func_, __LINE__) { __func__ }

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
        /**
         * @brief Non-owning pointer to the sample name.
         * @note Caller must ensure the pointed-to string outlives the
         *       process (e.g. a string literal or a namespace-scope
         *       `static constexpr char` array). The ScopedProfile
         *       array-reference constructor only rejects pointer decay;
         *       it does NOT verify static-storage.
         */
        const char *name{nullptr};
        int64_t start_ticks{0};  ///< QPC tick count at scope entry.
        uint32_t duration_us{0}; ///< Duration in microseconds (max ~71 minutes).
        uint32_t thread_id{0};   ///< Win32 thread ID of the recording thread.

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
         * @param name Non-owning pointer that must outlive the process. The
         *        pointer is stored as-is in the ring buffer and read
         *        asynchronously by export methods. Passing a pointer whose
         *        storage is released before process exit (std::string::c_str(),
         *        heap buffers, function-local arrays) is undefined behavior.
         *        Neither this entry point nor the ScopedProfile(const char
         *        (&)[N]) constructor enforces static-storage at compile time;
         *        array-reference binding accepts any array, so callers remain
         *        responsible for lifetime. Safe sources: string literals,
         *        `static constexpr char` arrays at namespace scope, and
         *        `__func__` (see [dcl.fct.def.general]/8).
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
         * @tparam N Deduced length of the bound array (including the trailing
         *         null terminator when the source is a string literal).
         * @param name Reference to a `const char` array. The array-reference
         *        parameter rejects decayed pointer sources (`std::string::
         *        c_str()`, `const char *` function arguments, `char *`
         *        buffers) at compile time, so those fail to bind and produce
         *        a compile error. However, C++ reference binding also accepts
         *        arrays with automatic storage (e.g. `char buf[N] = "...";`
         *        inside a function), which decays to a dangling pointer once
         *        the enclosing scope exits. This overload does NOT prove
         *        static storage; callers must still ensure the bound array
         *        outlives the process. Safe sources: string literals,
         *        namespace-scope `static constexpr char` arrays, and
         *        `__func__` (static-storage per [dcl.fct.def.general]/8).
         * @note The hot-path cost is unchanged: two pointer-sized stores
         *       (name pointer and thread id) plus the QPC read, same as
         *       the previous `const char*` signature.
         */
        template <size_t N>
        explicit ScopedProfile(const char (&name)[N]) noexcept
            : ScopedProfile(static_cast<const char *>(name), literal_tag{})
        {
        }
        ~ScopedProfile() noexcept;

        ScopedProfile(const ScopedProfile &) = delete;
        ScopedProfile &operator=(const ScopedProfile &) = delete;
        ScopedProfile(ScopedProfile &&) = delete;
        ScopedProfile &operator=(ScopedProfile &&) = delete;

    private:
        struct literal_tag
        {
        };

        ScopedProfile(const char *name, literal_tag) noexcept;

        const char *name_;
        int64_t start_ticks_;
        uint32_t thread_id_;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_PROFILER_HPP
