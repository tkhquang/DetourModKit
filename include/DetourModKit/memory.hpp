#ifndef DETOURMODKIT_MEMORY_HPP
#define DETOURMODKIT_MEMORY_HPP

/**
 * @file memory.hpp
 * @brief The v4 guarded-memory surface: fault-tolerant reads, writes, pointer-chain walks, and a page-protection guard.
 * @details Every operation here speaks the v4 value vocabulary -- `Address` for locations, `Region` for spans, `Prot`
 *          for protection, and `Result<T>` for fallible outcomes -- so a consumer never reinterpret_casts a raw integer
 *          at a call site and never branches on a per-domain error enum. The reads and writes are guarded: a faulting
 *          access (unmapped page, PAGE_NOACCESS / guard page, a page reprotected out from under a stale pointer) is
 *          turned into a `Result` error instead of terminating the host. The Structured Exception Handling that makes
 *          that possible (MSVC `__try` / MinGW vectored handler) lives ENTIRELY in the engine translation unit; this
 *          installed header pulls in no `<windows.h>`, no SEH, and no internal engine header, so it stays a clean public
 *          compile contract.
 *
 *          The surface is deliberately layered by safety:
 *          - `read` / `read_into` / `write` / `write_bytes` / `walk` are GUARDED: they validate, fault-protect, and
 *            report failure as an `Error`. Use them whenever the address may be stale.
 *          - `is_plausible_ptr` is a pure arithmetic pre-screen (no syscall, no access) for terminating bad pointer
 *            chains early.
 *          - the cache and `is_readable` / `is_writable` predicates answer protection questions for one-shot setup
 *            validation and diagnostics, NOT per-frame hot paths (each consults a lock and, on a miss, a VirtualQuery).
 *          - `unchecked::read` is the raw fast path: it performs NO validation and FAULTS THE HOST on an unreadable
 *            byte, and is discoverable only inside the `unchecked` namespace precisely so the danger is visible.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/defines.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"

#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace DetourModKit
{
    namespace memory
    {
        /**
         * @brief Inclusive lower bound of the canonical x64 user-mode address window.
         * @details The low 64 KiB is the reserved null-dereference region and is never a live pointer, so any value
         *          below this bound cannot be a valid object pointer. Paired with @ref USERSPACE_PTR_MAX it rejects
         *          stale or sentinel values with no syscall and no memory access.
         */
        inline constexpr std::uintptr_t USERSPACE_PTR_MIN = 0x10000;

        /**
         * @brief Exclusive upper bound of the canonical x64 user-mode address window.
         * @details Mapped user addresses sit below the 47-bit canonical split at 0x0000'8000'0000'0000; a value at or
         *          above this bound is a kernel-range or non-canonical address and cannot be a valid user-mode object
         *          pointer. Paired with @ref USERSPACE_PTR_MIN.
         */
        inline constexpr std::uintptr_t USERSPACE_PTR_MAX = 0x0000800000000000ULL;

        /// Maximum byte count a single @ref write_bytes call accepts before failing with ErrorCode::SizeTooLarge.
        inline constexpr std::size_t MAX_WRITE_SIZE = 64ULL * 1024 * 1024;

        /// Default number of region entries the protection cache holds.
        inline constexpr std::size_t DEFAULT_CACHE_SIZE = 256;
        /// Default cache entry lifetime, in milliseconds, before a re-query.
        inline constexpr unsigned int DEFAULT_CACHE_EXPIRY_MS = 50;
        /// Minimum permitted cache size.
        inline constexpr std::size_t MIN_CACHE_SIZE = 1;
        /// Default number of cache shards, striped to reduce reader contention.
        inline constexpr std::size_t DEFAULT_CACHE_SHARD_COUNT = 16;
        /// Default multiplier bounding the cache's hard maximum size relative to its configured size.
        inline constexpr std::size_t DEFAULT_MAX_CACHE_SIZE_MULTIPLIER = 2;

        /**
         * @brief Structural plausibility test for an x64 user-mode pointer.
         * @param address The address to test.
         * @return True only when @p address lies in [@ref USERSPACE_PTR_MIN, @ref USERSPACE_PTR_MAX).
         * @details A pure arithmetic guard with no memory access and no syscall: the first-class pointer-sanity gate
         *          meant to terminate pointer-chain traversals early on obviously bad values (null, small enum-shaped
         *          integers, non-canonical addresses) before paying for a guarded read. It does NOT prove the pointer
         *          is mapped or that the target object is the expected type; pair it with a module range check
         *          (@ref module_of) and a guarded @ref read for full validation. It is `constexpr`, so it can gate
         *          compile-time checks.
         */
        [[nodiscard]] inline constexpr bool is_plausible_ptr(Address address) noexcept
        {
            const std::uintptr_t value = address.raw();
            return value >= USERSPACE_PTR_MIN && value < USERSPACE_PTR_MAX;
        }

        /**
         * @brief Guarded copy of @p out.size() bytes from @p address into @p out.
         * @param address Source address.
         * @param out Destination byte span. An empty span is a successful no-op.
         * @return An empty `Result` on full success; `ErrorCode::ReadFaulted` (with the faulting address in
         *         `Error::detail`) on any fault or rejected argument.
         * @details The byte-level read primitive every typed @ref read forwards to. The copy runs under the engine's
         *          fault guard (MSVC `__try`, MinGW vectored handler), so a fault anywhere in the span -- including a
         *          multi-region read that crosses into unmapped or protected memory -- is swallowed and reported rather
         *          than terminating the host. An address below @ref USERSPACE_PTR_MIN, or a span whose end wraps the
         *          address space, is rejected without a read so a stale or sentinel pointer cannot raise a first-chance
         *          exception. On failure the contents of @p out are unspecified.
         * @note Callback-safe: allocates nothing, takes no lock, and on the established hot path issues no syscall.
         */
        [[nodiscard]] Result<void> read_into(Address address, std::span<std::byte> out) noexcept;

        /**
         * @brief Guarded typed read of a trivially copyable @p T at @p address.
         * @tparam T A trivially copyable type. It need not be default constructible: the bytes are read into untyped
         *           storage and reinterpreted with `std::bit_cast`, so no @p T object is constructed on the failure path
         *           and a type with a deleted default constructor can still be read.
         * @param address Source address.
         * @return The value on success, or the propagated @ref read_into error on a read fault.
         * @details Forwards to @ref read_into so the `__try` frame stays in the engine TU. On success the read
         * collapses
         *          to a single guarded copy of `sizeof(T)` bytes followed by a no-op bit_cast.
         * @note Callback-safe (see @ref read_into).
         */
        template <class T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] Result<T> read(Address address) noexcept
        {
            std::array<std::byte, sizeof(T)> storage{};
            if (auto outcome = read_into(address, storage); !outcome)
            {
                return std::unexpected(outcome.error());
            }
            return std::bit_cast<T>(storage);
        }

        /**
         * @brief Guarded write of a byte span to @p address, changing page protection only if it must.
         * @param address Destination address.
         * @param source Source byte span. An empty span is a successful no-op.
         * @return An empty `Result` on success; one of `ErrorCode::NullTargetAddress`, `NullSourceBytes`,
         * `SizeTooLarge`
         *         (over @ref MAX_WRITE_SIZE), `ProtectionChangeFailed`, `WriteFaulted` (the slow path made the page
         *         writable but the guarded copy faulted, e.g. a concurrent reprotect), or `ProtectionRestoreFailed` on
         *         failure.
         * @details A single primitive that serves both the per-frame data write and the one-shot code patch. It first
         *          attempts a guarded write that changes NO page protection: when the target is already writable -- a
         *          live game field, or any page held writable by a @ref ProtectGuard -- this fast path succeeds with no
         *          VirtualProtect and no instruction-cache flush, so writing through it every frame is a guarded copy,
         *          not a syscall storm. Only when that guarded write faults (the page is read-only or executable) does
         *          it take the slow path: change protection to writable, copy, flush the instruction cache, restore the
         *          original protection, and invalidate the affected cache range. Because protection is changed only on
         *          the slow path, holding a @ref ProtectGuard over a hot region keeps the writes inside it on the cheap
         *          path. The slow-path copy also runs under the fault guard: if the page is reprotected or unmapped out
         *          from under it mid-copy, the target may have been partially written, but the restore path and
         *          instruction-cache flush still run. If the restore succeeds the call fails with `WriteFaulted`; if the
         *          restore fails, `ProtectionRestoreFailed` takes priority.
         * @note Callback-safe on the fast path; the slow (protection-changing) path is setup/control-plane work.
         */
        [[nodiscard]] Result<void> write_bytes(Address address, std::span<const std::byte> source) noexcept;

        /**
         * @brief Guarded write of a trivially copyable @p T to @p address.
         * @tparam T A trivially copyable type. Its object representation is copied byte-for-byte; no @p T object is
         *           constructed at @p address.
         * @param address Destination address.
         * @param value Value whose object representation is written.
         * @return The propagated @ref write_bytes result.
         * @details Forwards to @ref write_bytes, so the same fast-path-then-unprotect policy and fault guard apply.
         * @note Callback-safe on the fast path (see @ref write_bytes).
         */
        template <class T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] Result<void> write(Address address, const T &value) noexcept
        {
            const auto storage = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
            return write_bytes(address, std::span<const std::byte>{storage});
        }

        /**
         * @brief Strict guarded write of a byte span that NEVER changes page protection.
         * @param address Destination address.
         * @param source Source byte span. An empty span is a successful no-op.
         * @return An empty `Result` on success; `ErrorCode::NullTargetAddress` / `NullSourceBytes` / `SizeTooLarge`
         *         (over @ref MAX_WRITE_SIZE) for a rejected argument, or `ErrorCode::WriteFaulted` when the target was
         *         not already writable.
         * @details The counterpart to @ref write_bytes for memory the target already keeps writable -- a live game
         *          field a hook updates every frame. Unlike @ref write_bytes it does NOT escalate: a read-only,
         *          executable, or no-access target FAILS CLOSED (`WriteFaulted`) rather than being unprotected and
         *          written. Use it when "write only if this page is already writable" is the intended contract: to
         *          keep a per-frame store off the VirtualProtect path, or to let a stale or mistargeted pointer that
         *          lands in read-only memory surface as an error instead of silently mutating it. For a one-shot code
         *          patch on a read-only / executable page use @ref write_bytes, which unprotects internally.
         * @note Callback-safe: allocates nothing, takes no lock, changes no protection, and issues no syscall on the
         *       fast path.
         */
        [[nodiscard]] Result<void> write_in_place(Address address, std::span<const std::byte> source) noexcept;

        /**
         * @brief Strict guarded write of a trivially copyable @p T that NEVER changes page protection.
         * @tparam T A trivially copyable type; its object representation is copied byte-for-byte.
         * @param address Destination address.
         * @param value Value whose object representation is written.
         * @return The propagated @ref write_in_place result.
         * @details Forwards to @ref write_in_place, so the same no-reprotect, fail-closed-if-not-writable contract
         *          applies. This is the typed per-frame store; see @ref write_in_place for when to prefer it over
         *          @ref write.
         * @note Callback-safe (see @ref write_in_place).
         */
        template <class T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] Result<void> write_in_place(Address address, const T &value) noexcept
        {
            const auto storage = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
            return write_in_place(address, std::span<const std::byte>{storage});
        }

        /**
         * @struct ChainStep
         * @brief One hop of a pointer-chain @ref walk: a byte offset plus the per-hop plausibility floor.
         * @details A walk applies each step's @ref offset to the running address; every step except the last is then
         *          dereferenced to obtain the next link, and that link must be at or above @ref min_valid (and below
         *          @ref USERSPACE_PTR_MAX) or the walk stops. @ref min_valid is the per-hop equivalent of
         *          @ref is_plausible_ptr's floor, defaulting to the canonical user-mode minimum; raise it for a hop
         *          whose link must live above a known module base.
         */
        struct ChainStep
        {
            /// Byte offset added to the running address at this hop (may be negative).
            std::ptrdiff_t offset;
            /// Lowest address the dereferenced link at this hop may hold; a link below it stops the walk.
            Address min_valid = Address{USERSPACE_PTR_MIN};
        };

        /**
         * @brief Resolves a multi-level pointer chain under the engine's fault guard, exposing every intermediate hop.
         * @param base Root address of the chain.
         * @param steps One @ref ChainStep per hop. Every offset except the last is added and dereferenced to obtain the
         *              next link; the final offset is added but not dereferenced, yielding the target field address. An
         *              empty span returns @p base unchanged.
         * @param trace Optional out-buffer. When non-empty, `trace[i]` receives the value resolved at hop `i` (the
         *              dereferenced link for an intermediate hop, the leaf address for the final hop), for as many hops
         *              as fit, and is populated for the successfully-walked prefix EVEN ON PARTIAL FAILURE so a caller
         *              can inspect how far the chain got.
         * @return The resolved leaf address on success; on failure, `ErrorCode::NullChain` for a null @p base with a
         *         non-empty chain, or `ErrorCode::ReadFaulted` with the FAILING HOP INDEX in `Error::detail` when an
         *         intermediate dereference faults or yields a link below that hop's @ref ChainStep::min_valid.
         * @details This is the precise primitive a consumer otherwise hand-rolls raw guarded blocks to get: per-hop
         *          gating, intermediate-link capture, and early-out at the first bad hop, none of which an all-or-nothing
         *          read can express. The returned address is not itself dereferenced or range-checked; the caller reads
         *          it (typically via @ref read).
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<Address> walk(Address base, std::span<const ChainStep> steps,
                                           std::span<Address> trace = {}) noexcept;

        /**
         * @brief Convenience @ref walk taking bare offsets, flooring every hop at @ref USERSPACE_PTR_MIN.
         * @param base Root address of the chain.
         * @param offsets Byte offsets applied left to right (see the @ref ChainStep overload for the hop semantics).
         * @param trace Optional intermediate-capture buffer (see the @ref ChainStep overload).
         * @return The resolved leaf address, or the same errors as the @ref ChainStep overload.
         * @details The common chain shape carries no per-hop floor, so this overload accepts a plain `{0x18, 0x40}`
         *          offset list and applies the default plausibility floor to each dereferenced link. It is exactly the
         *          @ref ChainStep overload with every `min_valid` defaulted.
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<Address> walk(Address base, std::span<const std::ptrdiff_t> offsets,
                                           std::span<Address> trace = {}) noexcept;

        /**
         * @class ProtectGuard
         * @brief Move-only RAII page-protection change: applies a @ref Prot to a @ref Region and restores it on scope
         *        exit.
         * @details Built only through @ref make so a guard can never exist without a successful protection change to
         *          unwind. Hold one over a region that is patched or written repeatedly: the original protection is
         *          captured at construction and restored by the destructor, and any @ref write_bytes inside the guarded
         *          window stays on its cheap no-reprotect fast path because the page is already writable. Restoration is
         *          best-effort (a destructor cannot report failure); a caller needing to observe the restore result
         *          should re-apply protection explicitly instead of relying on the destructor.
         * @note Single-protection-region precondition: the guard captures ONE prior protection value (the first page's,
         *       as `VirtualProtect` reports it) and restores the whole span to it. Applied to a range that spans pages
         *       of DIFFERENT protection, the restore flattens them all to the first page's protection. Scope a guard to
         *       a region that lies within a single protection block -- the normal case for a patch site or a field --
         *       and split a mixed-protection range into one guard per block.
         * @note @ref make and the destructor each call @ref invalidate_range for the guarded span, so the protection
         *       cache never answers a later @ref is_readable / @ref is_writable from a snapshot taken before the guard
         *       changed (or restored) the protection.
         */
        class ProtectGuard
        {
        public:
            /**
             * @brief Changes @p region to @p protection and returns a guard that restores the prior protection.
             * @param region The span whose protection is changed; an empty region fails closed. It should lie within a
             *               single protection block (see the class note on the single-region precondition).
             * @param protection The protection to apply for the guard's lifetime.
             * @return An armed guard on success; `ErrorCode::OutOfMemory` if the guard's capture state could not be
             *         allocated (no protection change is attempted, so nothing leaks), or
             *         `ErrorCode::ProtectionChangeFailed` (with the OS error in `Error::extra`) if the protection could
             *         not be changed.
             * @details The capture state is allocated BEFORE the protection is changed, so a failed allocation cannot
             *          strand the region in the new protection with no guard to restore it. On success the changed range
             *          is dropped from the protection cache (@ref invalidate_range).
             */
            [[nodiscard]] static Result<ProtectGuard> make(Region region, Prot protection) noexcept;

            ProtectGuard(ProtectGuard &&other) noexcept;
            ProtectGuard &operator=(ProtectGuard &&other) noexcept;
            ProtectGuard(const ProtectGuard &) = delete;
            ProtectGuard &operator=(const ProtectGuard &) = delete;

            /// Restores the original page protection unless the guard was moved-from or @ref release was called.
            ~ProtectGuard() noexcept;

            /// True while the guard is armed (it will restore on destruction); false after a move or @ref release.
            [[nodiscard]] explicit operator bool() const noexcept;

            /// Disarms the guard so the destructor leaves the changed protection in place rather than restoring it.
            void release() noexcept;

        private:
            // Private so the only way to obtain a guard is make(), which guarantees the protection change succeeded.
            ProtectGuard() noexcept;

            // The captured base/size/old-protection live in the engine TU so this header carries no Win32 type.
            struct Impl;
            std::unique_ptr<Impl> m_impl;
        };

        /**
         * @brief Resolves the mapped image span of the module that owns @p address.
         * @param address Any address inside the target module.
         * @return The owning module's @ref Region, or an empty Region when @p address is null, falls inside no loaded
         *         module, or the module's PE headers do not validate.
         * @details The address-keyed module lookup: given a resolved pointer, answer "which module is this in, and what
         *          is its full image span?" so a caller can range-check the pointer against its own image
         *          (@ref Region::own), the host image (@ref Region::host), or a third module. The result is cached per
         *          module handle for the process lifetime, so repeated probes degenerate to a loader lookup plus a hash
         *          hit.
         * @note Setup/control-plane only -- issues a loader lookup; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] Region module_of(Address address) noexcept;

        /**
         * @brief Reports whether a module with the given base name is currently loaded in the process.
         * @param basename The module's file name as the loader knows it (e.g. "kernel32.dll"); a bare name, not a path.
         * @param case_insensitive When true (the default, matching Windows module-name semantics) the comparison
         *                         ignores case.
         * @return True when a loaded module's base name matches @p basename.
         * @details Reuses the loader's own module table rather than a from-scratch enumeration, so a consumer need not
         *          reimplement a PSAPI walk just to ask "is this DLL present?".
         * @note Setup/control-plane only -- queries the loader; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] bool is_module_loaded(std::string_view basename, bool case_insensitive = true) noexcept;

        /**
         * @struct MemoryStats
         * @brief Allocation-free snapshot of protection-cache configuration and counters.
         * @details Every field mirrors a value reported by @ref get_cache_stats. Counters are loaded with relaxed
         *          atomics and the live-entry totals are summed under the shard reader guard, so the struct is a
         *          consistent-per-field but not globally-atomic view. @ref hit_rate_percent is -1.0 when no queries have
         *          been tracked (hits + misses == 0).
         */
        struct MemoryStats
        {
            /// Configured number of cache shards.
            std::size_t shard_count = 0;
            /// Configured soft entry capacity per shard.
            std::size_t max_entries_per_shard = 0;
            /// Hard maximum entries per shard (capacity * multiplier), averaged across shards.
            std::size_t hard_max_per_shard = 0;
            /// Cache-entry expiry window in milliseconds.
            unsigned int expiry_ms = 0;
            /// Cumulative cache hits.
            std::uint64_t hits = 0;
            /// Cumulative cache misses.
            std::uint64_t misses = 0;
            /// Cumulative range invalidations.
            std::uint64_t invalidations = 0;
            /// Cumulative in-flight query coalesces.
            std::uint64_t coalesced_queries = 0;
            /// Cumulative on-demand cleanup passes.
            std::uint64_t on_demand_cleanups = 0;
            /// Live entry count summed across all shards at snapshot time.
            std::size_t total_entries = 0;
            /// hits / (hits + misses) * 100, or -1.0 when no queries have been tracked.
            double hit_rate_percent = -1.0;
        };

        /**
         * @brief Initializes the protection-region cache used by @ref is_readable / @ref is_writable.
         * @param cache_size Desired number of entries across the cache.
         * @param expiry_ms Cache entry expiry time in milliseconds.
         * @param shard_count Number of cache shards for concurrent access.
         * @return True if the cache is ready for use (newly or previously initialized), false on allocation failure.
         * @details Only the first call configures the cache; later calls return true without reconfiguring. Starts a
         *          background cleanup thread when the platform permits, falling back to on-demand cleanup otherwise. On
         *          MinGW it also installs the process-wide vectored fault handler the guarded reads rely on, so a
         *          guarded read never has to fall back to a per-call VirtualQuery.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] bool init_cache(std::size_t cache_size = DEFAULT_CACHE_SIZE,
                                      unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS,
                                      std::size_t shard_count = DEFAULT_CACHE_SHARD_COUNT);

        /**
         * @brief Clears all entries from the protection cache, leaving it initialized.
         * @details Invalidates all cached region information; the background cleanup thread keeps running.
         */
        void clear_cache() noexcept;

        /**
         * @brief Shuts the cache down and joins the background cleanup thread.
         * @details Call before module unload to terminate the cleanup thread cleanly. After shutdown the cache cannot
         * be
         *          reused without re-initialization. Under loader lock the thread is detached rather than joined to
         *          avoid deadlock, and on MinGW the vectored fault handler is drained and removed.
         * @note Setup/control-plane only.
         */
        void shutdown_cache() noexcept;

        /**
         * @brief Returns an allocation-free snapshot of cache statistics.
         * @return A @ref MemoryStats snapshot.
         */
        [[nodiscard]] MemoryStats get_memory_stats() noexcept;

        /**
         * @brief Returns a human-readable string of cache statistics, built over @ref get_memory_stats.
         * @return A formatted statistics string. Prefer @ref get_memory_stats for telemetry consumers.
         */
        [[nodiscard]] std::string get_cache_stats();

        /**
         * @brief Invalidates cache entries overlapping @p range, forcing a re-query on the next probe.
         * @param range The span whose cached protection state is dropped. An empty range is a no-op.
         * @details Used after external protection changes (a VirtualProtect by other code) so a later @ref is_readable
         *          does not answer from stale protection. @ref write_bytes performs this automatically on its
         *          protection-changing slow path.
         */
        void invalidate_range(Region range) noexcept;

        /**
         * @enum ReadableStatus
         * @brief Tri-state result for the non-blocking readability check.
         */
        enum class ReadableStatus
        {
            /// The region is committed and readable.
            Readable,
            /// The region is not committed, not readable, or the arguments were rejected.
            NotReadable,
            /// The answer could not be obtained without blocking (shard lock contended, cache miss, or init in flight).
            Unknown
        };

        /**
         * @brief Reports whether @p range is committed and readable.
         * @param range The span to check. An empty range returns false.
         * @return True when the entire range is readable and committed.
         * @warning Not a per-dereference hot-path gate: a hit takes a shard reader lock and a miss issues a
         * VirtualQuery,
         *          and the answer is a time-of-check/time-of-use snapshot. For hot reads of game-owned pointers, call a
         *          guarded @ref read and check the `Result` instead, optionally pre-screened by @ref is_plausible_ptr.
         */
        [[nodiscard]] bool is_readable(Region range) noexcept;

        /**
         * @brief Reports whether @p range is committed and writable.
         * @param range The span to check. An empty range returns false.
         * @return True when the entire range is writable and committed.
         * @warning Carries the same hot-path cost and time-of-check/time-of-use caveat as @ref is_readable; reserve it
         *          for one-shot setup validation. To write, prefer attempting a guarded @ref write_bytes which fails
         *          closed.
         */
        [[nodiscard]] bool is_writable(Region range) noexcept;

        /**
         * @brief Non-blocking readability check that returns @ref ReadableStatus::Unknown rather than stalling.
         * @param range The span to check. An empty range returns @ref ReadableStatus::NotReadable.
         * @return @ref ReadableStatus::Readable / NotReadable for a definite answer, or @ref ReadableStatus::Unknown
         *         when answering would require blocking (a contended shard try-lock or a cache miss, once the cache is
         *         initialized), so a latency-sensitive caller can fall back to a guarded @ref read instead of stalling.
         * @details Before @ref init_cache (or after @ref shutdown_cache) there is no cache to consult, so it issues a
         *          single blocking VirtualQuery and returns a definite Readable / NotReadable, never Unknown.
         */
        [[nodiscard]] ReadableStatus is_readable_nonblocking(Region range) noexcept;

        /**
         * @namespace DetourModKit::memory::unchecked
         * @brief The raw, validation-free fast path. Every entry point here FAULTS THE HOST on an unreadable byte.
         * @details Quarantined in its own namespace so the danger is visible at the call site: nothing here guards,
         * gates,
         *          or reports an error, because the contract is "the caller has already proven this access is safe".
         */
        namespace unchecked
        {
            /**
             * @brief Unguarded typed read of a trivially copyable @p T at @p address.
             * @tparam T A trivially copyable type (need not be default constructible; the read goes through untyped
             *           storage and `std::bit_cast`).
             * @param address Source address. EVERY byte of `[address, address + sizeof(T))` MUST be committed and
             *                 readable; this performs NO validation and a violation faults the host process.
             * @return The value at @p address.
             * @details The fastest possible read: a single inlined copy with no SEH, no VirtualQuery, and no cache
             *          lookup. Use it only for pointers the caller has proven are alive this frame (for example a game
             *          object known to be live). For anything that may be stale, use the guarded @ref read.
             * @note Callback-safe by construction (it does nothing but copy), but UNSAFE on an invalid address.
             * @note A debug-only `assert(is_readable(...))` catches a violated precondition during development: in a
             *       Debug build (NDEBUG unset) a stale or unmapped address trips the assert at the offending call site
             *       instead of a raw access violation deep in the copy. The whole expression is compiled out under
             *       NDEBUG, so a Release build pays nothing and keeps the "single inlined copy" cost. In Release there
             *       is therefore NO diagnostic at all -- an invalid address faults the host exactly as documented above,
             *       which is the price of the `unchecked` fast path; reach for the guarded @ref read when the address
             *       might be stale.
             */
            template <class T>
                requires std::is_trivially_copyable_v<T>
            [[nodiscard]] T read(Address address) noexcept
            {
                // Dev-only guard: is_readable() consults the protection cache / VirtualQuery, which is why it lives on
                // the setup path and not here, so it must NOT run in Release -- assert() discards the entire call under
                // NDEBUG, leaving the fast path a bare copy. In Debug it converts the caller's "I have proven this is
                // safe" contract into a checkable invariant.
                assert(
                    is_readable(Region{address, sizeof(T)}) &&
                    "unchecked::read<T>: address is not fully readable; the caller's safety precondition is violated");
                std::array<std::byte, sizeof(T)> storage{};
                std::memcpy(storage.data(), address.as<const void *>(), sizeof(T));
                return std::bit_cast<T>(storage);
            }
        } // namespace unchecked
    } // namespace memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_HPP
