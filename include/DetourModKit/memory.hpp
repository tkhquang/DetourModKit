#ifndef DETOURMODKIT_MEMORY_HPP
#define DETOURMODKIT_MEMORY_HPP

#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <initializer_list>
#include <optional>
#include <span>
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
    [[nodiscard]] constexpr std::string_view memory_error_to_string(MemoryError error) noexcept
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
         * @details Sets up an internal cache to store information about memory regions, reducing overhead of frequent
         *          VirtualQuery system calls.
         * @param cache_size The desired number of entries in the cache. Defaults to 256.
         * @param expiry_ms Cache entry expiry time in milliseconds. Defaults to 50ms.
         * @param shard_count Number of cache shards for concurrent access. Defaults to 16.
         * @return true if the cache is ready for use (newly or previously initialized), false on failure.
         * @note Only the first call configures the cache; subsequent calls return true without reconfiguring. To
         *       reconfigure, call shutdown_cache() first.
         * @note Starts a background cleanup thread that runs periodically.
         */
        [[nodiscard]] bool init_cache(size_t cache_size = DEFAULT_CACHE_SIZE,
                                      unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS,
                                      size_t shard_count = DEFAULT_CACHE_SHARD_COUNT);

        /**
         * @brief Clears all entries from the memory region cache.
         * @details Invalidates all currently cached memory region information. The background cleanup thread continues
         *          running.
         */
        void clear_cache() noexcept;

        /**
         * @brief Shuts down the memory cache and stops the background cleanup thread.
         * @details Call this before program exit to cleanly terminate the cleanup thread. After calling shutdown, the
         *          cache cannot be reused without re-initialization.
         */
        void shutdown_cache() noexcept;

        /**
         * @struct MemoryStats
         * @brief Allocation-free snapshot of memory-cache configuration and counters.
         * @details Every field mirrors a value reported by get_cache_stats(). Counters are loaded with relaxed
         *          atomics and the live-entry totals are summed under the shard reader guard, so the struct is a
         *          consistent-per-field but not globally-atomic view. hit_rate_percent is -1.0 when no queries have
         *          been tracked (hits + misses == 0), matching the formatter's "N/A" branch.
         */
        struct MemoryStats
        {
            /// Configured number of cache shards.
            size_t shard_count = 0;
            /// Configured soft entry capacity per shard.
            size_t max_entries_per_shard = 0;
            /// Hard max entries per shard (capacity * multiplier), averaged across shards as the string reports it.
            size_t hard_max_per_shard = 0;
            /// Cache-entry expiry window in milliseconds.
            unsigned int expiry_ms = 0;
            /// Cumulative cache hits.
            uint64_t hits = 0;
            /// Cumulative cache misses.
            uint64_t misses = 0;
            /// Cumulative range invalidations.
            uint64_t invalidations = 0;
            /// Cumulative in-flight query coalesces.
            uint64_t coalesced_queries = 0;
            /// Cumulative on-demand cleanup passes.
            uint64_t on_demand_cleanups = 0;
            /// Live entry count summed across all shards at snapshot time.
            size_t total_entries = 0;
            /// hits / (hits + misses) * 100, or -1.0 when no queries have been tracked.
            double hit_rate_percent = -1.0;
        };

        /**
         * @brief Returns an allocation-free snapshot of memory-cache statistics.
         * @details Value-returning counterpart to get_cache_stats(): reads the same counters and walks the shards
         *          under the same reader guard, but builds no string. Prefer it for telemetry/metrics consumers, and
         *          use get_cache_stats() for human-readable log lines.
         * @return MemoryStats POD snapshot.
         */
        [[nodiscard]] MemoryStats get_memory_stats() noexcept;

        /**
         * @brief Retrieves statistics about the memory cache usage.
         * @details Returns cache hits, misses, and hit rate information as a human-readable string built over
         *          get_memory_stats().
         * @return std::string A human-readable string of cache statistics.
         */
        [[nodiscard]] std::string get_cache_stats();

        /**
         * @brief Invalidates cache entries that overlap with the specified address range.
         * @details Used to force re-query of memory region info after external changes such as VirtualProtect calls by
         *          other code.
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
         * @warning Not a per-dereference gate for hot paths. A cache hit still takes a shard reader lock and a cache
         *          miss issues a
         *          VirtualQuery syscall; placing this in front of every field read on a per-frame or per-object path
         *          multiplies that cost by the read count and is dominated by cache misses when the target addresses
         *          change. It is also a time-of-check to time-of-use illusion: the page state can change between the
         *          check and the access. For hot-path reads of game-owned pointers, drop the predicate and read
         *          directly under a single
         *          SEH frame (@ref seh_read, @ref seh_read_chain), optionally pre-screened by @ref
         *          plausible_userspace_ptr and a module or heap range check. Reserve is_readable for one-shot setup
         *          validation and diagnostics.
         */
        [[nodiscard]] bool is_readable(const void *address, size_t size);

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
         * @details Attempts a try-lock on the cache shard. Returns Unknown if the lock cannot be acquired, allowing
         *          callers on latency-sensitive threads to fall back to SEH instead of stalling.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return ReadableStatus indicating readable, not readable, or unknown (lock busy).
         */
        [[nodiscard]] ReadableStatus is_readable_nonblocking(const void *address, size_t size);

        /**
         * @brief Reads a pointer-sized value at (base + offset), returning 0 on fault.
         * @details On MSVC, uses SEH (__try/__except) to catch access violations with zero overhead on the success
         *          path. On MinGW, the read runs under a process-wide vectored exception handler (installed lazily), so
         *          the success path is a guarded copy with no syscall and any fault -- unmapped,
         *          PAGE_NOACCESS/guard, or a page reprotected out from under a stale cache entry -- is swallowed and
         *          returned as 0. Suitable for hot paths that already manage their own error recovery.
         * @note The MinGW path consults no cache; the fault guard makes a cache probe unnecessary. If the vectored
         *       handler cannot be installed it falls back to VirtualQuery-validated reads. Either way the function
         *       exposes no caller-observable cache state.
         * @param base The base address to read from.
         * @param offset Byte offset added to base before dereferencing.
         * @return The pointer-sized value at the address, or 0 if the read faults.
         */
        [[nodiscard]] uintptr_t read_ptr_unsafe(uintptr_t base, ptrdiff_t offset) noexcept;

        /**
         * @brief Inclusive lower bound of the canonical x64 user-mode address window.
         * @details The low 64 KiB is the reserved null-dereference region and is never a live pointer, so any value
         *          below this bound cannot be a valid object pointer. Paired with @ref USERSPACE_PTR_MAX, the window
         *          rejects stale or sentinel values with no syscall and no memory access.
         */
        inline constexpr uintptr_t USERSPACE_PTR_MIN = 0x10000;

        /**
         * @brief Exclusive upper bound of the canonical x64 user-mode address window.
         * @details Mapped user addresses sit below the 47-bit canonical split at 0x0000'8000'0000'0000; a value at or
         *          above this bound is a kernel-range or non-canonical address and cannot be a valid user-mode object
         *          pointer. Paired with @ref USERSPACE_PTR_MIN.
         */
        inline constexpr uintptr_t USERSPACE_PTR_MAX = 0x0000800000000000ULL;

        /**
         * @brief Structural plausibility test for an x64 user-mode pointer.
         * @details Returns true only when @p p lies in
         *          [@ref USERSPACE_PTR_MIN, @ref USERSPACE_PTR_MAX). This is a pure arithmetic guard with no memory
         *          access and no syscall, intended to terminate pointer-chain traversals early on obviously bad values
         *          (null, small enum-shaped integers, non-canonical addresses) before paying for an SEH-guarded read.
         *          It does not prove the pointer is mapped or that the target object is the expected type; pair it with
         *          a module or heap range check and an SEH-guarded read for full validation.
         * @param ptr The pointer value to test.
         * @return true if @p ptr is a plausible user-mode pointer, false otherwise.
         */
        [[nodiscard]] inline constexpr bool plausible_userspace_ptr(uintptr_t ptr) noexcept
        {
            return ptr >= USERSPACE_PTR_MIN && ptr < USERSPACE_PTR_MAX;
        }

        /**
         * @brief Fastest pointer dereference with user-mode range validity guards only.
         * @details Validates the source address (base + offset) before dereferencing, then applies the same guard to
         *          the loaded value. Both the source and the result must sit in the user-mode window (min_valid, @ref
         *          USERSPACE_PTR_MAX): the floor rejects the null page and guard pages (addresses below 0x10000 are
         *          never valid usermode pointers on Windows), and the ceiling rejects kernel-range and non-canonical
         *          addresses. Both checks terminate stale/dangling pointer chain traversals early without requiring an
         *          SEH frame.
         *
         *          This function does NOT provide fault protection against unmapped or freed memory above min_valid. If
         *          the pointer chain may reference deallocated heap memory or unmapped regions, use read_ptr_unsafe()
         *          instead (SEH-protected on MSVC, vectored-handler-guarded on MinGW).
         *
         *          The "unchecked" in the name refers to the absence of OS-level memory validation in release builds
         *          (no SEH, no VirtualQuery, no cache lookup). Only user-mode range guards are applied. Intended for
         *          hot paths where the caller can guarantee structural pointer validity (e.g. game objects known to be
         *          alive this frame).
         * @note Debug builds (NDEBUG undefined) add an assert that the source is readable, so passing a stale or
         *       unmapped pointer is caught during development instead of faulting the host. The probe is compiled out
         *       in release, leaving the hot path a single guarded memcpy. Use @ref seh_read_chain or @ref
         *       read_ptr_unsafe for pointers that may not be alive.
         * @param base The base address to read from.
         * @param offset Byte offset added to base before dereferencing.
         * @param min_valid Minimum address value to accept (default 0x10000).
         * @return The pointer-sized value at the address, or 0 if either the source address or the dereferenced value
         *         falls outside the user-mode window (min_valid, @ref USERSPACE_PTR_MAX).
         * @note The lower bound is exclusive here, whereas plausible_userspace_ptr treats the same bound as inclusive.
         *       The difference is intentional:
         *       this function performs an unguarded dereference, so it is one address more conservative and never
         *       blindly reads the boundary itself, while plausible_userspace_ptr only screens a value arithmetically.
         */
        [[nodiscard]] inline uintptr_t read_ptr_unchecked(uintptr_t base, ptrdiff_t offset,
                                                          uintptr_t min_valid = 0x10000) noexcept
        {
            const auto src = base + static_cast<uintptr_t>(offset);
            // Accept the source only strictly inside the user-mode window (min_valid, USERSPACE_PTR_MAX). The floor is
            // deliberately exclusive: this dereference is unguarded in release, so min_valid itself is treated as the
            // first address NOT trusted for a blind read (one address more conservative than plausible_userspace_ptr,
            // which is a pure no-deref pre-screen and so is inclusive at the same bound). The ceiling rejects
            // kernel-range and non-canonical sources; together with the floor it also subsumes any pointer-arithmetic
            // wraparound, because a ptrdiff_t offset is too small to carry base back into this window (a non-negative
            // offset cannot overflow past 2^64 from a userspace base, and an underflowing negative offset lands either
            // below min_valid or above the ceiling), so no separate wrap check is needed.
            if (src <= min_valid || src >= USERSPACE_PTR_MAX)
                return 0;
            // Debug-build footgun guard. In release the dereference below is a bare memcpy: a stale or unmapped src
            // faults and takes down the host. This primitive is only for pointers the caller has proven are alive this
            // frame, so in debug we confirm src is readable and assert otherwise, surfacing misuse during development.
            // The probe compiles out in release (NDEBUG), keeping the hot path a single guarded memcpy.
            assert(is_readable(reinterpret_cast<const void *>(src), sizeof(uintptr_t)) &&
                   "read_ptr_unchecked: source pointer is not readable (stale/unmapped); "
                   "use seh_read_chain or read_ptr_unsafe for pointers that may not be alive");
            uintptr_t addr{0};
            std::memcpy(&addr, reinterpret_cast<const void *>(src), sizeof(addr));
            // Apply the same user-mode window to the loaded value so a structurally valid source that yields a
            // kernel-range or non-canonical pointer is rejected rather than propagated to the next link of the chain.
            return (addr > min_valid && addr < USERSPACE_PTR_MAX) ? addr : 0;
        }

        /**
         * @brief Checks if a specified memory region is writable.
         * @details Verifies if the memory range has write permissions and is committed.
         * @param address Starting address of the memory region.
         * @param size Number of bytes in the memory region to check.
         * @return true if the entire region is writable, false otherwise.
         * @warning Carries the same hot-path cost and time-of-check to time-of-use caveat as @ref is_readable. When a
         *          hook receives a pointer the engine just wrote through, that pointer is already writable; gating the
         *          store behind this predicate adds a lock and a periodic VirtualQuery for no safety gain. Write
         *          directly (under SEH if the address may be stale) and reserve is_writable for one-shot setup
         *          validation.
         */
        [[nodiscard]] bool is_writable(void *address, size_t size);

        /**
         * @brief Writes a sequence of bytes to a target memory address.
         * @details Handles changing memory protection, performs the write operation, and restores original protection.
         *          Also flushes instruction cache. Automatically invalidates the affected cache range. If num_bytes
         *          exceeds MAX_WRITE_SIZE the function performs no write and returns MemoryError::SizeTooLarge.
         * @param target_address Destination memory address.
         * @param source_bytes Pointer to the source buffer containing data to write.
         * @param num_bytes Number of bytes to write. Must not exceed MAX_WRITE_SIZE.
         * @return std::expected<void, MemoryError> on success, or the specific error on failure.
         */
        [[nodiscard]] std::expected<void, MemoryError> write_bytes(std::byte *target_address,
                                                                   const std::byte *source_bytes, size_t num_bytes);

        /**
         * @struct ModuleRange
         * @brief Mapped address range of a loaded PE image.
         * @details A range is considered valid when @ref base is non-zero and @ref end strictly exceeds @ref base.
         *          Default-constructed instances (both fields zero) report @ref valid() as false so callers can return
         *          an "absent" range without optional.
         */
        struct ModuleRange
        {
            /// Mapped base address (equal to the HMODULE value).
            uintptr_t base = 0;
            /// Exclusive upper bound (base + SizeOfImage from the PE OptionalHeader).
            uintptr_t end = 0;

            /// True iff this range is populated (base != 0 && end > base).
            [[nodiscard]] constexpr bool valid() const noexcept { return base != 0 && end > base; }
        };

        /**
         * @brief Resolves the mapped range of the module containing @p address.
         * @details Looks up the owning module via
         *          GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
         *          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, ...), then reads SizeOfImage from the PE
         *          OptionalHeader behind a seh_read_bytes() guard. The result is cached per HMODULE for the process
         *          lifetime so repeated probes degenerate to a single GetModuleHandleEx call plus a hash lookup.
         * @note The cache assumes mapped modules do not unload at addresses later reused by a different image. Game
         *       mods do not unload host modules; consumers that load and free DLLs at runtime should treat cached
         *       entries for an unloaded module's HMODULE as stale.
         * @note Every call issues a GetModuleHandleEx lookup even on a cache hit. For a hot path that repeatedly checks
         *       whether a pointer lives inside one known module, capture @ref own_module_range or @ref
         *       host_module_range once and test with @ref contains, which is a branch-only comparison with no syscall.
         * @param address Any address inside the target module. nullptr returns std::nullopt without a syscall.
         * @return The module's range, or std::nullopt if @p address does not fall inside any loaded module or the PE
         *         headers are unreadable.
         */
        [[nodiscard]] std::optional<ModuleRange> module_range_for(const void *address) noexcept;

        /**
         * @brief Mapped range of the calling DLL (or EXE if DetourModKit is statically linked into the host process).
         * @details DetourModKit is a static library, so the link target of @ref own_module_range itself is whichever
         *          DLL/EXE consumed the static library. Cached on first call via a function-local static, so subsequent
         *          calls are a single atomic load on the fast path.
         * @return The owning module's range, or an invalid ModuleRange if the lookup or PE-header read failed (only
         *         possible under loader lock teardown or on corrupted images).
         */
        [[nodiscard]] ModuleRange own_module_range() noexcept;

        /**
         * @brief Mapped range of the host process EXE.
         * @details Equivalent to module_range_for(GetModuleHandleW(nullptr)) with the same per-process caching as @ref
         *          own_module_range. Useful for sanity-checking that a freshly resolved vtable pointer lives inside the
         *          game image rather than on the heap or in an injected helper DLL.
         * @return The EXE's range, or an invalid ModuleRange on lookup failure.
         */
        [[nodiscard]] ModuleRange host_module_range() noexcept;

        /**
         * @brief Tests whether @p ptr lies inside @p range.
         * @return true iff @p range is valid and @p ptr is in [base, end).
         */
        [[nodiscard]] constexpr bool contains(ModuleRange range, uintptr_t ptr) noexcept
        {
            return range.valid() && ptr >= range.base && ptr < range.end;
        }

        /**
         * @brief SEH-guarded raw memory copy from @p addr into @p out.
         * @details On MSVC, the copy runs inside a __try / __except frame whose filter accepts the foreign-read fault
         *          set (EXCEPTION_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION, and EXCEPTION_IN_PAGE_ERROR for a
         *          file-backed page that fails to page in), so any such fault in the middle of the copy unwinds cleanly
         *          and the function returns false. On MinGW the copy runs under a process-wide vectored exception
         *          handler that claims the same fault set (no per-call VirtualQuery on the success path); a fault
         *          anywhere in the span is swallowed and the function returns false. If the handler cannot be installed
         *          it falls back to VirtualQuery-based validation of every region the read spans.
         *
         *          The function is the underlying primitive for the typed @ref seh_read template and is exposed
         *          directly for callers that need to read a contiguous buffer of bytes (for example NUL-terminated
         *          strings of unknown length).
         * @param addr  Source address. Values below 0x10000 (the Windows
         *              reserved low-address range) are rejected without a read so stale or sentinel pointers cannot
         *              cause a first-chance exception.
         * @param out   Destination buffer. nullptr returns false.
         * @param bytes Number of bytes to copy. Zero returns true (no-op).
         * @return true on full success; false on any fault or invalid argument. On failure the contents of @p out are
         *         unspecified.
         */
        [[nodiscard]] bool seh_read_bytes(uintptr_t addr, void *out, size_t bytes) noexcept;

        /**
         * @brief SEH-guarded typed read of a trivially copyable T at @p addr.
         * @details Forwards to @ref seh_read_bytes so the underlying __try frame lives in the translation unit that
         *          defines it. The bytes are read into untyped storage and reinterpreted with std::bit_cast, so no T
         *          object is constructed and the failure path runs no T constructor or destructor. On success the read
         *          collapses to a single memcpy of sizeof(T) bytes followed by a no-op bit_cast.
         * @tparam T A trivially copyable type. Trivial copyability is what std::bit_cast requires and what makes a raw
         *           byte copy a valid reconstruction of the value. T need not be default constructible, so
         *           non-default-constructible POD-like types (e.g. structs with a deleted default constructor) can be
         *           read.
         * @param addr Source address. Values below 0x10000 are rejected without a read; see @ref seh_read_bytes.
         * @return The value on success, std::nullopt on any read fault.
         */
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] std::optional<T> seh_read(uintptr_t addr) noexcept
        {
            std::array<std::byte, sizeof(T)> storage{};
            if (!seh_read_bytes(addr, storage.data(), sizeof(T)))
                return std::nullopt;
            return std::bit_cast<T>(storage);
        }

        /**
         * @brief Resolves a multi-level pointer chain under a single fault guard.
         * @details Walks Cheat-Engine-style pointer-chain semantics: starting at @p base, every offset except the last
         *          is added and dereferenced to obtain the next link, and the final offset is added but not
         *          dereferenced, yielding the address of the target field. With offsets {o0, o1, o2} the result is
         *          (*(*(base + o0) + o1)) + o2.
         *
         *          The entire walk runs inside one fault guard. On x64 MSVC the
         *          __try is table-driven (described by .pdata/.xdata emitted at compile time) and adds no runtime setup
         *          on the no-fault path whether the chain uses one guard or N, so the win over calling @ref seh_read
         *          once per link is not SEH-frame setup:
         *          it is one out-of-line call instead of N, each intermediate link kept in a register instead of
         *          round-tripped through std::optional, and a single argument validation. On MinGW (no SEH) the saving
         *          is concrete: one guarded helper call instead of N, each intermediate link read through @ref
         *          read_ptr_unsafe (guarded by the process-wide vectored handler) and the final address computed
         *          without a read.
         *
         *          Each intermediate link is screened with @ref plausible_userspace_ptr; a link that faults or yields
         *          an implausible pointer aborts the walk and returns std::nullopt. The returned address is not
         *          dereferenced and not range-checked by this function; the caller reads it (typically via @ref
         *          seh_read or @ref seh_read_chain).
         * @param base Root address of the chain.
         * @param offsets Byte offsets applied left to right. An empty span returns @p base unchanged.
         * @return The resolved target address, or std::nullopt if any intermediate dereference faults or produces an
         *         implausible pointer.
         */
        [[nodiscard]] std::optional<uintptr_t> seh_resolve_chain(uintptr_t base,
                                                                 std::span<const ptrdiff_t> offsets) noexcept;

        /**
         * @brief Convenience overload accepting a braced offset list.
         * @see seh_resolve_chain(uintptr_t, std::span<const ptrdiff_t>)
         */
        [[nodiscard]] inline std::optional<uintptr_t>
        seh_resolve_chain(uintptr_t base, std::initializer_list<ptrdiff_t> offsets) noexcept
        {
            return seh_resolve_chain(base, std::span<const ptrdiff_t>(offsets.begin(), offsets.size()));
        }

        /**
         * @brief Resolves a pointer chain and reads a raw byte range at its end.
         * @details Performs the same walk as @ref seh_resolve_chain and then copies @p bytes from the resolved address
         *          into @p out under one fault guard, so a fault anywhere in the resolve or the terminal read takes the
         *          same failure path and cannot leave a partially walked chain observable to the caller. On MinGW the
         *          chain is resolved via @ref read_ptr_unsafe and the terminal read uses @ref seh_read_bytes.
         * @param base Root address of the chain.
         * @param offsets Byte offsets applied left to right (see @ref seh_resolve_chain). An empty span reads at @p
         *                base.
         * @param out Destination buffer. nullptr returns false.
         * @param bytes Number of bytes to copy. Zero returns true (no-op).
         * @return true on a fully successful resolve and read; false if any intermediate link faults or is implausible,
         *         or the terminal read faults. On failure the contents of @p out are unspecified.
         */
        [[nodiscard]] bool seh_read_chain_bytes(uintptr_t base, std::span<const ptrdiff_t> offsets, void *out,
                                                size_t bytes) noexcept;

        /**
         * @brief Resolves a pointer chain and reads a typed value at its end.
         * @details Forwards to @ref seh_read_chain_bytes, so the chain walk and the typed read share a single fault
         *          guard. The bytes are read into untyped storage and reinterpreted with std::bit_cast, so no T object
         *          is constructed on the failure path.
         * @tparam T A trivially copyable type (see @ref seh_read; T need not be default constructible).
         * @param base Root address of the chain.
         * @param offsets Byte offsets applied left to right (see @ref seh_resolve_chain).
         * @return The value on success, std::nullopt if any link faults or is implausible or the terminal read faults.
         */
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] std::optional<T> seh_read_chain(uintptr_t base, std::span<const ptrdiff_t> offsets) noexcept
        {
            std::array<std::byte, sizeof(T)> storage{};
            if (!seh_read_chain_bytes(base, offsets, storage.data(), sizeof(T)))
                return std::nullopt;
            return std::bit_cast<T>(storage);
        }

        /**
         * @brief Convenience overload accepting a braced offset list.
         * @see seh_read_chain(uintptr_t, std::span<const ptrdiff_t>)
         */
        template <typename T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] std::optional<T> seh_read_chain(uintptr_t base, std::initializer_list<ptrdiff_t> offsets) noexcept
        {
            return seh_read_chain<T>(base, std::span<const ptrdiff_t>(offsets.begin(), offsets.size()));
        }
    } // namespace Memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_HPP
