#ifndef DETOURMODKIT_MEMORY_HPP
#define DETOURMODKIT_MEMORY_HPP

/**
 * @file memory.hpp
 * @brief The guarded-memory surface: fault-tolerant reads, writes, pointer-chain walks, and a protection guard.
 * @details Each guarded entry point reports a fault as an `Error`, unless the guard-page re-arm in `[B-20]` fails.
 * @warning `[B-100]` Under the loader lock, call only the Callback-safe entry points in this header. Cache startup and
 *          the exact-case module lookup fail closed.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/defines.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"

#include <array>
#include <bit>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace DetourModKit
{
    namespace detail
    {
        /// True for a `std::initializer_list` specialization.
        template <class T> inline constexpr bool is_initializer_list_v = false;
        template <class U> inline constexpr bool is_initializer_list_v<std::initializer_list<U>> = true;

        /**
         * @brief True for every `std::ranges::view` and every `std::initializer_list`.
         * @details `[B-21]` Typed `write<T>` rejects every view, even a byte span. `write_bytes` and `write_in_place`
         *          write the viewed bytes of a contiguous byte view.
         */
        template <class T>
        inline constexpr bool is_non_owning_view_v = std::ranges::view<T> || is_initializer_list_v<T>;

        /**
         * @brief Opt-in trait for an aggregate whose every object representation is valid to read from foreign bytes.
         * @details Before you specialize it, verify the whole transitive object representation. Also verify that no
         *          padding byte holds a value that you interpret. `std::array` opts in when its element type qualifies.
         */
        template <class T> struct enable_representation_safe_aggregate : std::false_type
        {
        };

        /// True when @p T explicitly opts into representation-safe aggregate reads.
        template <class T>
        inline constexpr bool enable_representation_safe_aggregate_v =
            enable_representation_safe_aggregate<std::remove_cv_t<T>>::value;

        /** @brief True when @p E has a fixed underlying type, so [dcl.enum]/8 admits every underlying value. */
        template <class E>
        concept fixed_underlying_enum = std::is_enum_v<E> && requires { E{std::underlying_type_t<E>{}}; };

        /** @brief True for a binary floating-point type with no padding bits. MinGW's x87 `long double` fails it. */
        template <class F> [[nodiscard]] constexpr bool padding_free_binary_float() noexcept
        {
            using Limits = std::numeric_limits<F>;
            if constexpr (!Limits::is_iec559 || Limits::radix != 2 || Limits::max_exponent <= 0 || Limits::digits <= 0)
            {
                return false;
            }
            else
            {
                const int exponent_bits =
                    static_cast<int>(std::bit_width(static_cast<unsigned long long>(Limits::max_exponent)));
                return 1 + exponent_bits + (Limits::digits - 1) == static_cast<int>(sizeof(F) * CHAR_BIT);
            }
        }

        /// @cond
        template <class T> struct representation_read_value
        {
            using type = T;
        };

        template <class T, std::size_t Size> struct representation_read_value<T[Size]>
        {
            using type = std::array<typename representation_read_value<T>::type, Size>;
        };

        template <class T> using representation_read_value_t = typename representation_read_value<T>::type;

        template <class T>
        [[nodiscard]] representation_read_value_t<T>
        decode_foreign_representation(const std::array<std::byte, sizeof(T)> &storage) noexcept
        {
            static_assert(
                sizeof(representation_read_value_t<T>) == sizeof(T),
                "a built-in array read requires the equivalent std::array to have identical size"
            );
            return std::bit_cast<representation_read_value_t<T>>(storage);
        }

        template <class T> [[nodiscard]] constexpr bool representation_safe() noexcept
        {
            using U = std::remove_cv_t<T>;
            if constexpr (std::is_same_v<U, bool>)
                return false;
            else if constexpr (std::is_bounded_array_v<U>)
                return representation_safe<std::remove_extent_t<U>>();
            else if constexpr (std::is_unbounded_array_v<U>)
                return false;
            else if constexpr (std::is_integral_v<U>)
                return true;
            else if constexpr (std::is_floating_point_v<U>)
                return padding_free_binary_float<U>();
            else if constexpr (std::is_enum_v<U>)
                // [dcl.enum]/8 gives `enum class E : bool` only the two bool values, so the base must qualify too.
                return fixed_underlying_enum<U> && representation_safe<std::underlying_type_t<U>>();
            else if constexpr (std::is_pointer_v<U>)
                return true;
            else if constexpr (std::is_member_pointer_v<U> || std::is_null_pointer_v<U>)
                return false;
            else
                return (std::is_class_v<U> || std::is_union_v<U>) && std::is_trivially_copyable_v<U> &&
                       enable_representation_safe_aggregate_v<U>;
        }

        template <class T, std::size_t Size>
        struct enable_representation_safe_aggregate<std::array<T, Size>> : std::bool_constant<representation_safe<T>()>
        {
        };

        template <> struct enable_representation_safe_aggregate<Address> : std::true_type
        {
        };
        /// @endcond

        static_assert(
            std::is_trivially_copyable_v<Address> && std::is_standard_layout_v<Address> &&
                sizeof(Address) == sizeof(std::uintptr_t) && alignof(Address) == alignof(std::uintptr_t),
            "Address participates in representation-safe reads only while it is exactly one padding-free "
            "std::uintptr_t; a stored flag or a wider member would make read<Address> unsound"
        );

        /**
         * @brief True when every bit pattern of the object representation of @p T is a valid value of @p T.
         * @details The domain is an allowlist. Copy any other type as raw bytes with @ref memory::read_into.
         *          - Every integral type except `bool`. Decode `bool` with @ref memory::read_bool.
         *          - A padding-free binary float: `float`, `double`, and `long double` only on MSVC.
         *          - An enumeration whose fixed underlying type is in the domain. The value can match no enumerator.
         *          - An object or function pointer, under the Windows x64 ABI. The value has no pointer provenance.
         *            Screen it with @ref memory::is_plausible_ptr. Read through it only by a guarded route.
         *          - A bounded built-in array or `std::array` of an element type in the domain.
         *          - @ref Address, and a class or union opted in through @ref enable_representation_safe_aggregate.
         */
        template <class T> inline constexpr bool is_representation_safe_v = representation_safe<T>();
    } // namespace detail

    namespace memory
    {
        /// Inclusive lower bound of the x64 user-mode pointer window. The reserved low 64 KiB holds no object.
        inline constexpr std::uintptr_t USERSPACE_PTR_MIN = 0x10000;

        /// Exclusive upper bound of the x64 user-mode pointer window, at the 47-bit canonical split.
        inline constexpr std::uintptr_t USERSPACE_PTR_MAX = 0x0000800000000000ULL;

        /// Largest span that each write entry point accepts. A larger span fails with `ErrorCode::SizeTooLarge`.
        inline constexpr std::size_t MAX_WRITE_SIZE = 64ULL * 1024 * 1024;

        /// Default number of region entries across the protection cache.
        inline constexpr std::size_t DEFAULT_CACHE_SIZE = 256;
        /// Default expiry window of a cache entry, in milliseconds, before a re-query.
        inline constexpr unsigned int DEFAULT_CACHE_EXPIRY_MS = 50;
        /// Minimum permitted cache size.
        inline constexpr std::size_t MIN_CACHE_SIZE = 1;
        /// Default number of cache shards.
        inline constexpr std::size_t DEFAULT_CACHE_SHARD_COUNT = 16;
        /// Default ratio of the hard entry maximum of a shard to its configured capacity.
        inline constexpr std::size_t DEFAULT_MAX_CACHE_SIZE_MULTIPLIER = 2;

        /**
         * @brief True when @p address lies in [@ref USERSPACE_PTR_MIN, @ref USERSPACE_PTR_MAX). It proves no mapping.
         * @note Callback-safe.
         */
        [[nodiscard]] inline constexpr bool is_plausible_ptr(Address address) noexcept
        {
            const std::uintptr_t value = address.raw();
            return value >= USERSPACE_PTR_MIN && value < USERSPACE_PTR_MAX;
        }

        /**
         * @brief Guarded copy of @p out.size() bytes from @p address into @p out. An empty @p out is a no-op success.
         * @return An empty `Result`, or `ErrorCode::OverlappingRanges`, with nothing read, if @p out intersects the
         *         source. Otherwise `ErrorCode::ReadFaulted` for a source span that wraps, leaves
         *         [@ref USERSPACE_PTR_MIN, @ref USERSPACE_PTR_MAX), or holds an unreadable byte, unless the guard-page
         *         re-arm in `[B-20]` fails. On failure the contents of @p out are unspecified.
         * @details `Error::detail` holds an unreadable source address. A scalar typed @ref read names its first
         *          unreadable byte. A larger span can name a later byte of the same region. A span rejected before any
         *          access, and the MinGW `VirtualQuery` fallback, report @p address.
         * @note Callback-safe: on the established fast path it allocates nothing, takes no lock, and issues no syscall.
         */
        [[nodiscard]] Result<void> read_into(Address address, std::span<std::byte> out) noexcept;

        /**
         * @brief Guarded typed read of a representation-safe @p T, which need not be default constructible.
         * @return The value, or the @ref read_into error. A top-level bounded built-in array returns as the equivalent
         *         nested `std::array`.
         * @note Callback-safe (see @ref read_into).
         */
        template <class T>
            requires(std::is_trivially_copyable_v<T> && detail::is_representation_safe_v<T>)
        [[nodiscard]] Result<detail::representation_read_value_t<T>> read(Address address) noexcept
        {
            std::array<std::byte, sizeof(T)> storage{};
            if (auto outcome = read_into(address, storage); !outcome)
            {
                return std::unexpected(outcome.error());
            }
            return detail::decode_foreign_representation<T>(storage);
        }

        /**
         * @brief Guarded checked decode of one foreign byte into a `bool`.
         * @return `false` for a byte of `0` and `true` for `1`. A read fault returns the @ref read_into error. Any
         *         other byte returns `ErrorCode::InvalidRepresentation` with the source address in `Error::detail`.
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<bool> read_bool(Address address) noexcept;

        /**
         * @brief Guarded data write. It changes page protection only if a first attempt without a change faults.
         * @param source An empty span is a no-op success, but a null @p address still fails with `NullTargetAddress`.
         * @return An empty `Result`, or `ErrorCode::NullTargetAddress`, `NullSourceBytes`, `SizeTooLarge` (over
         *         @ref MAX_WRITE_SIZE), `OverlappingRanges` (nothing written), `ProtectionChangeFailed`, `WriteFaulted`
         *         (nothing written), @ref ErrorCode::WriteMayBePartial, `InstructionFlushFailed`, or
         *         `ProtectionRestoreFailed`.
         * @details A successful first attempt issues no flush. A first attempt that faults past the first byte flushes
         *          the whole request if any region of it is executable. Use @ref patch_code for bytes that execute.
         *
         *          The slow path makes each `VirtualQuery` region writable, with no execute added to a data page. It
         *          then copies, flushes executable regions, restores each prior protection, and invalidates the cached
         *          range. A failed change, for example over too many regions, returns `WriteMayBePartial` if the first
         *          attempt faulted past the first byte, and otherwise `ProtectionChangeFailed`. A slow-path copy fault
         *          returns `WriteFaulted` after the restore and flush if both attempts faulted on the first byte, and
         *          otherwise `WriteMayBePartial`. `ProtectionRestoreFailed` outranks every other slow-path error.
         * @note Callback-safe on the fast path. The slow path changes protection and is setup/control-plane work.
         */
        [[nodiscard]] Result<void> write_bytes(Address address, std::span<const std::byte> source) noexcept;

        /**
         * @brief Guarded write of the object representation of @p value through @ref write_bytes, which it returns.
         * @note Callback-safe on the fast path (see @ref write_bytes).
         */
        template <class T>
            requires std::is_trivially_copyable_v<T> && (!detail::is_non_owning_view_v<std::remove_cvref_t<T>>)
        [[nodiscard]] Result<void> write(Address address, const T &value) noexcept
        {
            const auto storage = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
            return write_bytes(address, std::span<const std::byte>{storage});
        }

        /**
         * @brief Guarded code patch: writes @p source at @p address and flushes the instruction cache for the target.
         * @return An empty `Result`, or an error of @ref write_bytes. `InstructionFlushFailed` means that the bytes
         *         landed but the flush failed.
         * @details The argument rules and the slow path match @ref write_bytes, except that every path that can modify
         *          the target flushes, even on already-writable code.
         * @warning The write is not atomic. `ProtectionRestoreFailed` outranks `WriteMayBePartial`, which outranks
         *          `InstructionFlushFailed`.
         * @note Callback-safe on the fast path. The slow path changes protection and is setup/control-plane work.
         */
        [[nodiscard]] Result<void> patch_code(Address address, std::span<const std::byte> source) noexcept;

        /**
         * @brief Strict guarded write of a byte span that never changes page protection.
         * @return An empty `Result`, or an argument error of @ref write_bytes under its rules. `WriteFaulted`, with no
         *         byte changed, when the first target byte is not writable, as on a read-only or execute-read page.
         *         `WriteMayBePartial` when a later byte faulted after the copy reached a writable page.
         * @warning The write is not atomic across a writability seam, and the changed prefix of `WriteMayBePartial` is
         *          indeterminate and can be empty. Size a per-frame store so that it cannot cross a seam.
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<void> write_in_place(Address address, std::span<const std::byte> source) noexcept;

        /**
         * @brief Strict guarded write of the object representation of @p value through @ref write_in_place.
         * @note A `std::span<std::byte>` or other contiguous byte view writes its viewed bytes, not the view object.
         * @note Callback-safe (see @ref write_in_place).
         */
        template <class T>
            requires std::is_trivially_copyable_v<T> && (!detail::is_non_owning_view_v<std::remove_cvref_t<T>>)
        [[nodiscard]] Result<void> write_in_place(Address address, const T &value) noexcept
        {
            const auto storage = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
            return write_in_place(address, std::span<const std::byte>{storage});
        }

        /**
         * @brief One hop of a pointer-chain @ref walk. The walk adds @ref offset to the current address, then
         *        dereferences the result on every hop except the last.
         */
        struct ChainStep
        {
            /// Byte offset of this hop. It can be negative.
            std::ptrdiff_t offset;
            /// Floor of the dereferenced link. A link outside [min_valid, @ref USERSPACE_PTR_MAX) stops the walk.
            Address min_valid = Address{USERSPACE_PTR_MIN};
        };

        /**
         * @brief Resolves a pointer chain under the fault guard and reports each intermediate hop.
         * @param trace `trace[i]` receives the dereferenced link or the final leaf of hop `i`, for as many hops as fit.
         *              The walk fills `trace` for each completed hop, even when a later hop fails.
         * @return The leaf address, which the walk does not read, or @p base for an empty chain. `ErrorCode::NullChain`
         *         for a null @p base with a non-empty chain. `ErrorCode::ReadFaulted` for a faulted dereference, a link
         *         outside its @ref ChainStep range, or a leaf that wraps or leaves
         *         [@ref USERSPACE_PTR_MIN, @ref USERSPACE_PTR_MAX). `Error::detail` holds the failed hop index.
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<Address>
        walk(Address base, std::span<const ChainStep> steps, std::span<Address> trace = {}) noexcept;

        /**
         * @brief Pointer-chain @ref walk over bare offsets, with every hop floored at @ref USERSPACE_PTR_MIN.
         * @return The @ref ChainStep overload result, or `ErrorCode::SizeTooLarge` for more than 32 offsets.
         * @note Callback-safe (see @ref read_into). Route a longer chain through the @ref ChainStep overload.
         */
        [[nodiscard]] Result<Address>
        walk(Address base, std::span<const std::ptrdiff_t> offsets, std::span<Address> trace = {}) noexcept;

        /**
         * @brief Move-only guard that changes a @ref Region to a @ref Prot until scope exit.
         * @details The guard captures and restores each `VirtualQuery` region of the span separately. Destructor
         *          restoration is best-effort. To observe the result, call @ref restore.
         * @note @ref make, @ref restore, the destructor, and move-assignment each invalidate the cached range.
         *       Move-assignment first restores the region of the replaced guard.
         */
        class ProtectGuard
        {
        public:
            /**
             * @brief Changes @p region to @p protection and returns a guard that restores the prior protection.
             * @return An armed guard, or `ErrorCode::OutOfMemory` with no protection changed.
             *         `ErrorCode::ProtectionChangeFailed` for a null or empty region, with `Error::extra` zero. The
             *         same code, with the OS error in `Error::extra`, for a failed change or too many protection
             *         regions. The call first rolls back each changed region. `ErrorCode::ProtectionRestoreFailed` if
             *         that rollback failed.
             * @note Setup/control-plane only: the guard allocates and issues `VirtualProtect` calls.
             */
            [[nodiscard]] static Result<ProtectGuard> make(Region region, Prot protection) noexcept;

            ProtectGuard(ProtectGuard &&other) noexcept;
            ProtectGuard &operator=(ProtectGuard &&other) noexcept;
            ProtectGuard(const ProtectGuard &) = delete;
            ProtectGuard &operator=(const ProtectGuard &) = delete;

            /// Restores the original page protection if the guard is still armed.
            ~ProtectGuard() noexcept;

            /// True while the guard is armed. False after a move, @ref release, or @ref restore.
            [[nodiscard]] explicit operator bool() const noexcept;

            /**
             * @brief Disarms the guard, so its destructor leaves the changed protection in place.
             * @details If no other guard holds a page, the next guard captures its current protection. If another
             *          guard still holds the page, the applied protection becomes that guard's restore baseline.
             * @note Setup/control-plane only: the call takes the protection ledger lock.
             */
            void release() noexcept;

            /**
             * @brief Restores the original protection now, reports the result, and disarms the guard.
             * @return An empty `Result`, also for a disarmed guard, or `ErrorCode::ProtectionRestoreFailed` with the OS
             *         error in `Error::extra`. The guard disarms on both outcomes.
             * @note Setup/control-plane only: the restore issues `VirtualProtect` calls.
             */
            [[nodiscard]] Result<void> restore() noexcept;

        private:
            // Only make() constructs a guard.
            ProtectGuard() noexcept;

            // The captured regions live in the implementation file, so this header holds no Win32 type.
            struct Impl;
            std::unique_ptr<Impl> m_impl;
        };

        /**
         * @brief Resolves the mapped image span of the module that owns @p address, from its current PE headers.
         * @return The module's @ref Region, or an empty Region when @p address is null, lies in no loaded module, or
         *         the module's PE headers do not validate.
         * @note Setup/control-plane only: the call issues a loader lookup and a guarded PE-header read.
         * @warning The Region does not pin the module. After an unload, the span references freed address space.
         */
        [[nodiscard]] Region module_of(Address address) noexcept;

        /**
         * @brief Reports whether a loaded module has the base name @p basename, for example "kernel32.dll", not a path.
         * @details A module path longer than `MAX_PATH` does not change the result in either case mode.
         * @note Setup/control-plane only: the query reaches the loader. An exact-case request fails closed under the
         *       loader lock.
         */
        [[nodiscard]] bool is_module_loaded(std::string_view basename, bool case_insensitive = true) noexcept;

        /**
         * @brief Allocation-free snapshot of the cache configuration and counters, not atomic as a whole.
         * @details @ref clear_cache on a running cache and a clean @ref shutdown_cache reset every counter except
         *          `lifecycle_violations`.
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
            /// Cache hits.
            std::uint64_t hits = 0;
            /// Cache misses.
            std::uint64_t misses = 0;
            /// Range invalidations.
            std::uint64_t invalidations = 0;
            /// In-flight query coalesces.
            std::uint64_t coalesced_queries = 0;
            /// On-demand cleanup passes.
            std::uint64_t on_demand_cleanups = 0;
            /// Live entry count summed across all shards at snapshot time.
            std::size_t total_entries = 0;
            /// hits / (hits + misses) * 100, or -1.0 when hits + misses is zero.
            double hit_rate_percent = -1.0;
            /// Recovered cleanup-thread lifecycle violations, normally zero. No call resets it.
            std::uint64_t lifecycle_violations = 0;
        };

        /**
         * @brief Initializes the protection cache that @ref is_readable and @ref is_writable consult.
         * @param cache_size Soft entry capacity across all shards. Each shard rounds its share up.
         * @return True when the cache runs. False when the lifecycle state blocks a start or setup fails, and readers
         *         then use the uncached `VirtualQuery` route.
         * @details A call while the cache runs returns true and keeps its configuration, with no loader-lock check. A
         *          call after @ref shutdown_cache uses its own arguments. A start fails if readers of a prior session
         *          outlive the drain deadline (see @ref shutdown_cache). A start creates the cleanup thread if the
         *          platform permits it, and otherwise cleanup runs on demand. On MinGW, a start also installs the
         *          guarded-read fault handler.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] bool init_cache(
            std::size_t cache_size = DEFAULT_CACHE_SIZE,
            unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS,
            std::size_t shard_count = DEFAULT_CACHE_SHARD_COUNT
        );

        /**
         * @brief Clears every protection-cache entry. The cache and its cleanup thread continue to run.
         * @note Setup/control-plane only: the clear takes every shard's exclusive lock.
         */
        void clear_cache() noexcept;

        /**
         * @brief Shuts the cache down and joins the cleanup thread, or detaches it under the loader lock.
         * @details The cache then needs @ref init_cache before reuse, and a permission query takes the uncached
         *          `VirtualQuery` route. The wait for admitted readers has a fixed deadline. A clean shutdown releases
         *          the cache storage and module reference. On deadline expiry, the cache retains both and records one
         *          @ref diagnostics::LeakSubsystem::MemoryCache event. A later @ref init_cache or @ref shutdown_cache
         *          can reclaim the storage after the stalled reader exits.
         *
         *          On MinGW, the call releases the guarded-read fault handler, except at process exit. The first
         *          guarded read can install that handler without @ref init_cache. Without a @ref Session, call this
         *          after the last guarded read of the module and before unload. Hook destruction off the loader lock
         *          takes a guarded read.
         *
         *          Session teardown blocks lazy handler installation until Session setup or @ref init_cache succeeds.
         *          In that interval, MinGW byte access uses the validated fallback, and guarded region scans fail
         *          closed. A VMT hook object update installs the handler only for that call. Without an active
         *          @ref Session, the call also returns the emit-chain TLS index of each idle diagnostics dispatcher,
         *          as @ref diagnostics::hook_lifecycle documents.
         * @note Setup/control-plane only.
         */
        void shutdown_cache() noexcept;

        /** @brief Returns an allocation-free snapshot of the cache statistics. */
        [[nodiscard]] MemoryStats get_memory_stats() noexcept;

        /** @brief Formats @ref get_memory_stats as a human-readable string. */
        [[nodiscard]] std::string get_cache_stats();

        /**
         * @brief Drops the cached protection of every entry that overlaps @p range. An empty range is a no-op.
         * @details Call it after other code changes protection. Paths in this header that change protection call it.
         * @note Setup/control-plane only: the invalidation mutates the cache shards.
         */
        void invalidate_range(Region range) noexcept;

        /** @brief Tri-state result of @ref is_readable_nonblocking. */
        enum class ReadableStatus : std::uint8_t
        {
            /// The region is committed and readable.
            Readable,
            /// The region is not committed, not readable, or the call rejected the arguments.
            NotReadable,
            /// The check needs a wait. @ref is_readable_nonblocking lists the cases.
            Unknown
        };

        /**
         * @brief Reports whether @p range is committed and readable. An empty range returns false.
         * @warning Do not call it on a per-dereference hot path. A hit takes a shard reader lock, and a miss can call
         *          `VirtualQuery` once per region. The answer is a time-of-check/time-of-use snapshot.
         * @note Setup/control-plane only. A hot path uses a guarded @ref read or @ref is_readable_nonblocking.
         */
        [[nodiscard]] bool is_readable(Region range) noexcept;

        /**
         * @brief Reports whether @p range is committed and writable. An empty range returns false.
         * @warning The @ref is_readable hot-path warning applies. To write, attempt a guarded @ref write_bytes instead.
         * @note Setup/control-plane only (see @ref is_readable).
         */
        [[nodiscard]] bool is_writable(Region range) noexcept;

        /**
         * @brief Readability check that returns @ref ReadableStatus::Unknown instead of a wait.
         * @return `NotReadable` for an empty range. `Unknown` only while the cache runs, after shard lock contention, a
         *         cache miss, or a concurrent shutdown that unpublished the shards.
         * @note Callback-safe while the cache runs: a try-lock probe with no allocation. If the cache does not run, the
         *       call blocks on a `VirtualQuery` walk of each region.
         */
        [[nodiscard]] ReadableStatus is_readable_nonblocking(Region range) noexcept;

        /** @brief Raw reads with no validation. Each entry point here faults the host on an unreadable byte. */
        namespace unchecked
        {
            /**
             * @brief Unguarded typed read of a representation-safe @p T.
             * @param address Every byte of `[address, address + sizeof(T))` must be committed, readable, and live for
             *                the current frame. Use the guarded @ref read for an address that can be stale.
             * @return The value. A top-level bounded built-in array returns as the equivalent nested `std::array`.
             * @note Callback-safe under `NDEBUG`. A Debug build can block or call `VirtualQuery` in its `is_readable`
             *       assertion.
             * @warning Under `NDEBUG`, an invalid address faults the host. A Debug build stops at the assertion.
             */
            template <class T>
                requires(std::is_trivially_copyable_v<T> && detail::is_representation_safe_v<T>)
            [[nodiscard]] detail::representation_read_value_t<T> read(Address address) noexcept
            {
                // assert() discards the is_readable() probe under NDEBUG.
                assert(
                    is_readable(Region{address, sizeof(T)}) &&
                    "unchecked::read<T>: address is not fully readable; the caller's safety precondition is violated"
                );
                std::array<std::byte, sizeof(T)> storage{};
                std::memcpy(storage.data(), address.as<const void *>(), sizeof(T));
                return detail::decode_foreign_representation<T>(storage);
            }
        } // namespace unchecked
    } // namespace memory
} // namespace DetourModKit

#endif // DETOURMODKIT_MEMORY_HPP
