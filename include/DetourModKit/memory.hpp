#ifndef DETOURMODKIT_MEMORY_HPP
#define DETOURMODKIT_MEMORY_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>

namespace DetourModKit
{
    /**
     * @enum MemoryError
     * @brief Error codes for memory operation failures.
     */
    enum class MemoryError
    {
        NullTargetAddress,
        NullSourceBytes,
        SizeTooLarge,
        ProtectionChangeFailed,
        ProtectionRestoreFailed
    };

    /**
     * @brief Converts a MemoryError to a human-readable string.
     * @param error The error code.
     * @return A string view describing the error.
     */
    constexpr std::string_view memory_error_to_string(MemoryError error) noexcept
    {
        switch (error)
        {
        case MemoryError::NullTargetAddress:
            return "Target address is null";
        case MemoryError::NullSourceBytes:
            return "Source bytes pointer is null";
        case MemoryError::SizeTooLarge:
            return "Write size exceeds maximum allowed";
        case MemoryError::ProtectionChangeFailed:
            return "Failed to change memory protection";
        case MemoryError::ProtectionRestoreFailed:
            return "Failed to restore original memory protection";
        default:
            return "Unknown memory error";
        }
    }

    // Maximum write size for write_bytes (64 MiB)
    inline constexpr size_t MAX_WRITE_SIZE = 64 * 1024 * 1024;

    // Memory cache configuration defaults
    inline constexpr size_t DEFAULT_CACHE_SIZE = 256;
    inline constexpr unsigned int DEFAULT_CACHE_EXPIRY_MS = 50;
    inline constexpr size_t MIN_CACHE_SIZE = 1;
    inline constexpr size_t DEFAULT_CACHE_SHARD_COUNT = 16;
    inline constexpr size_t DEFAULT_MAX_CACHE_SIZE_MULTIPLIER = 2;

    namespace Memory
    {
        /**
         * @brief Initializes the memory region cache with specified parameters.
         * @details Sets up an internal cache to store information about memory regions,
         *          reducing overhead of frequent VirtualQuery system calls.
         * @param cache_size The desired number of entries in the cache. Defaults to 256.
         * @param expiry_ms Cache entry expiry time in milliseconds. Defaults to 50ms.
         * @param shard_count Number of cache shards for concurrent access. Defaults to 16.
         * @return true if the cache is ready for use (newly or previously initialized), false on failure.
         * @note Only the first call configures the cache; subsequent calls return true without reconfiguring.
         *       To reconfigure, call shutdown_cache() first.
         * @note Starts a background cleanup thread that runs periodically.
         */
        [[nodiscard]] bool init_cache(size_t cache_size = DEFAULT_CACHE_SIZE,
                        unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS,
                        size_t shard_count = DEFAULT_CACHE_SHARD_COUNT);

        /**
         * @brief Clears all entries from the memory region cache.
         * @details Invalidates all currently cached memory region information.
         *         The background cleanup thread continues running.
         */
        void clear_cache();

        /**
         * @brief Shuts down the memory cache and stops the background cleanup thread.
         * @details Call this before program exit to cleanly terminate the cleanup thread.
         *         After calling shutdown, the cache cannot be reused without re-initialization.
         */
        void shutdown_cache();

        /**
         * @brief Retrieves statistics about the memory cache usage.
         * @details Returns cache hits, misses, and hit rate information.
         *          Statistics are only available in debug builds.
         * @return std::string A human-readable string of cache statistics.
         */
        std::string get_cache_stats();

        /**
         * @brief Invalidates cache entries that overlap with the specified address range.
         * @details Used to force re-query of memory region info after external changes
         *          such as VirtualProtect calls by other code.
         * @param address Starting address of the range to invalidate.
         * @param size Size of the range to invalidate.
         */
        void invalidate_range(const void *address, size_t size);

        /**
         * @brief Checks if a specified memory region is readable.
         * @details Verifies if the memory range has read permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is readable, false otherwise.
         */
        bool is_readable(const void *address, size_t size);

        /**
         * @enum ReadableStatus
         * @brief Tri-state result for non-blocking readability checks.
         */
        enum class ReadableStatus
        {
            Readable,
            NotReadable,
            Unknown
        };

        /**
         * @brief Non-blocking readability check that avoids contention on shared locks.
         * @details Attempts a try-lock on the cache shard. Returns Unknown if the lock
         *          cannot be acquired, allowing callers on latency-sensitive threads to
         *          fall back to SEH instead of stalling.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return ReadableStatus indicating readable, not readable, or unknown (lock busy).
         */
        ReadableStatus is_readable_nonblocking(const void *address, size_t size);

        /**
         * @brief Reads a pointer-sized value at (base + offset), returning 0 on fault.
         * @details On MSVC, uses SEH (__try/__except) to catch access violations with
         *          zero overhead on the success path. On MinGW, falls back to a single
         *          VirtualQuery guard before dereferencing (no cache interaction).
         *          Suitable for hot paths that already manage their own error recovery.
         * @note On MinGW the implementation additionally probes the cache via a
         *       non-blocking try_lock_shared before falling back to VirtualQuery,
         *       so cache hits avoid a syscall. This is invisible to callers; the
         *       function still exposes no caller-observable cache state.
         * @param base The base address to read from.
         * @param offset Byte offset added to base before dereferencing.
         * @return The pointer-sized value at the address, or 0 if the read faults.
         */
        uintptr_t read_ptr_unsafe(uintptr_t base, ptrdiff_t offset) noexcept;

        /**
         * @brief Fastest pointer dereference with low-address validity guards only.
         * @details Validates the source address (base + offset) before dereferencing,
         *          then rejects result values at or below min_valid. Addresses below
         *          0x10000 are never valid usermode pointers on Windows (null page +
         *          guard pages), so both checks terminate stale/dangling pointer chain
         *          traversals early without requiring an SEH frame.
         *
         *          This function does NOT provide fault protection against unmapped or
         *          freed memory above min_valid. If the pointer chain may reference
         *          deallocated heap memory or unmapped regions, use read_ptr_unsafe()
         *          instead (SEH-protected on MSVC, VirtualQuery-guarded on MinGW).
         *
         *          The "unchecked" in the name refers to the absence of OS-level
         *          memory validation (no SEH, no VirtualQuery, no cache lookup).
         *          Only low-address guards are applied. Intended for hot paths
         *          where the caller can guarantee structural pointer validity
         *          (e.g. game objects known to be alive this frame).
         * @param base The base address to read from.
         * @param offset Byte offset added to base before dereferencing.
         * @param min_valid Minimum address value to accept (default 0x10000).
         * @return The pointer-sized value at the address, or 0 if either the source
         *         address or the dereferenced value is at or below min_valid.
         */
        inline uintptr_t read_ptr_unchecked(uintptr_t base, ptrdiff_t offset,
                                            uintptr_t min_valid = 0x10000) noexcept
        {
            const auto src = base + static_cast<uintptr_t>(offset);
            if (src <= min_valid)
                return 0;
            uintptr_t addr{0};
            std::memcpy(&addr, reinterpret_cast<const void *>(src), sizeof(addr));
            return (addr > min_valid) ? addr : 0;
        }

        /**
         * @brief Checks if a specified memory region is writable.
         * @details Verifies if the memory range has write permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is writable, false otherwise.
         */
        bool is_writable(void *address, size_t size);

        /**
         * @brief Writes a sequence of bytes to a target memory address.
         * @details Handles changing memory protection, performs the write operation,
         *          and restores original protection. Also flushes instruction cache.
         *          Automatically invalidates the affected cache range.
         *          If numBytes exceeds MAX_WRITE_SIZE the function performs no write
         *          and returns MemoryError::SizeTooLarge.
         * @param targetAddress Destination memory address.
         * @param sourceBytes Pointer to the source buffer containing data to write.
         * @param numBytes Number of bytes to write. Must not exceed MAX_WRITE_SIZE.
         * @return std::expected<void, MemoryError> on success, or the specific error on failure.
         */
        [[nodiscard]] std::expected<void, MemoryError> write_bytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes);

        /**
         * @struct ModuleRange
         * @brief Mapped address range of a loaded PE image.
         * @details A range is considered valid when @ref base is non-zero and
         *          @ref end strictly exceeds @ref base. Default-constructed
         *          instances (both fields zero) report @ref valid() as false
         *          so callers can return an "absent" range without optional.
         */
        struct ModuleRange
        {
            uintptr_t base = 0; ///< Mapped base address (equal to the HMODULE value).
            uintptr_t end = 0;  ///< Exclusive upper bound (base + SizeOfImage from the PE OptionalHeader).

            /// True iff this range is populated (base != 0 && end > base).
            [[nodiscard]] constexpr bool valid() const noexcept { return base != 0 && end > base; }
        };

        /**
         * @brief Resolves the mapped range of the module containing @p address.
         * @details Looks up the owning module via
         *          GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
         *          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, ...), then
         *          reads SizeOfImage from the PE OptionalHeader behind a
         *          seh_read_bytes() guard. The result is cached per HMODULE
         *          for the process lifetime so repeated probes degenerate to
         *          a single GetModuleHandleEx call plus a hash lookup.
         * @note The cache assumes mapped modules do not unload at addresses
         *       later reused by a different image. Game mods do not unload
         *       host modules; consumers that load and free DLLs at runtime
         *       should treat cached entries for an unloaded module's HMODULE
         *       as stale.
         * @param address Any address inside the target module. nullptr returns
         *                std::nullopt without a syscall.
         * @return The module's range, or std::nullopt if @p address does not
         *         fall inside any loaded module or the PE headers are unreadable.
         */
        [[nodiscard]] std::optional<ModuleRange> module_range_for(const void *address) noexcept;

        /**
         * @brief Mapped range of the calling DLL (or EXE if DetourModKit is
         *        statically linked into the host process).
         * @details DetourModKit is a static library, so the link target of
         *          @ref own_module_range itself is whichever DLL/EXE consumed
         *          the static library. Cached on first call via a function-local
         *          static, so subsequent calls are a single atomic load on the
         *          fast path.
         * @return The owning module's range, or an invalid ModuleRange if the
         *         lookup or PE-header read failed (only possible under loader
         *         lock teardown or on corrupted images).
         */
        [[nodiscard]] ModuleRange own_module_range() noexcept;

        /**
         * @brief Mapped range of the host process EXE.
         * @details Equivalent to module_range_for(GetModuleHandleW(nullptr))
         *          with the same per-process caching as @ref own_module_range.
         *          Useful for sanity-checking that a freshly resolved vtable
         *          pointer lives inside the game image rather than on the
         *          heap or in an injected helper DLL.
         * @return The EXE's range, or an invalid ModuleRange on lookup failure.
         */
        [[nodiscard]] ModuleRange host_module_range() noexcept;

        /**
         * @brief Tests whether @p p lies inside @p range.
         * @return true iff @p range is valid and @p p is in [base, end).
         */
        [[nodiscard]] constexpr bool contains(ModuleRange range, uintptr_t p) noexcept
        {
            return range.valid() && p >= range.base && p < range.end;
        }

        /**
         * @brief SEH-guarded raw memory copy from @p addr into @p out.
         * @details On MSVC, the copy runs inside a __try / __except
         *          (EXCEPTION_ACCESS_VIOLATION | STATUS_GUARD_PAGE_VIOLATION)
         *          frame, so any access violation in the middle of the copy
         *          unwinds cleanly and the function returns false. On MinGW
         *          the implementation falls back to VirtualQuery-based
         *          validation of every region the read spans before issuing
         *          the memcpy; this is race-prone against concurrent
         *          VirtualProtect but is the best a non-SEH toolchain can do.
         *
         *          The function is the underlying primitive for the typed
         *          @ref seh_read template and is exposed directly for
         *          callers that need to read a contiguous buffer of bytes
         *          (for example NUL-terminated strings of unknown length).
         * @param addr  Source address. Values below 0x10000 (the Windows
         *              reserved low-address range) are rejected without a
         *              read so stale or sentinel pointers cannot cause a
         *              first-chance exception.
         * @param out   Destination buffer. nullptr returns false.
         * @param bytes Number of bytes to copy. Zero returns true (no-op).
         * @return true on full success; false on any fault or invalid argument.
         *         On failure the contents of @p out are unspecified.
         */
        [[nodiscard]] bool seh_read_bytes(uintptr_t addr, void *out, size_t bytes) noexcept;

        /**
         * @brief SEH-guarded typed read of a trivially copyable T at @p addr.
         * @details Forwards to @ref seh_read_bytes so the underlying __try
         *          frame lives in the translation unit that defines it. Local
         *          variables with non-trivial destructors are not permitted in
         *          functions that use __try (MSVC C2712); restricting T to
         *          trivially copyable types avoids that restriction here and
         *          keeps the value-construction free of any side effects that
         *          would survive the failure path.
         *
         *          On the success path the implementation collapses to a
         *          single memcpy of sizeof(T) bytes; on failure the optional
         *          carries no value and no T destructor is invoked.
         * @tparam T A trivially copyable type. Required by C++23 concept.
         * @param addr Source address. Values below 0x10000 are rejected
         *             without a read; see @ref seh_read_bytes.
         * @return The value on success, std::nullopt on any read fault.
         */
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] std::optional<T> seh_read(uintptr_t addr) noexcept
        {
            T value;
            if (!seh_read_bytes(addr, &value, sizeof(T)))
                return std::nullopt;
            return value;
        }
    } // namespace Memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_HPP
