#ifndef DETOURMODKIT_MEMORY_HPP
#define DETOURMODKIT_MEMORY_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

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
         * @param base The base address to read from.
         * @param offset Byte offset added to base before dereferencing.
         * @return The pointer-sized value at the address, or 0 if the read faults.
         */
        uintptr_t read_ptr_unsafe(uintptr_t base, ptrdiff_t offset) noexcept;

        /**
         * @brief Unchecked inline pointer dereference with low-address validity guards only.
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
         *          Intended for hot paths where the caller can guarantee structural
         *          pointer validity (e.g. game objects known to be alive this frame).
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
            const auto addr = *reinterpret_cast<const uintptr_t *>(src);
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
         * @param targetAddress Destination memory address.
         * @param sourceBytes Pointer to the source buffer containing data to write.
         * @param numBytes Number of bytes to write (capped at MAX_WRITE_SIZE).
         * @return std::expected<void, MemoryError> on success, or the specific error on failure.
         */
        [[nodiscard]] std::expected<void, MemoryError> write_bytes(std::byte *targetAddress, const std::byte *sourceBytes, size_t numBytes);
    } // namespace Memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_HPP
