#ifndef DETOURMODKIT_MEMORY_HPP
#define DETOURMODKIT_MEMORY_HPP

/**
 * @file memory.hpp
 * @brief The guarded-memory surface: fault-tolerant reads, writes, pointer-chain walks, and a protection guard.
 * @details A guarded access turns a fault into a `Result` error instead of a host termination. The fault guard (MSVC
 *          `__try`, MinGW vectored handler) lives entirely in the engine translation unit, so this header pulls in no
 *          `<windows.h>` and no SEH.
 *
 *          The surface is layered by safety:
 *          - `read`, `read_into`, `write`, `write_bytes`, and `walk` are GUARDED. They validate, fault-protect, and
 *            report failure as an `Error`. Use them whenever the address can be stale.
 *          - `is_plausible_ptr` is a pure arithmetic pre-screen with no syscall and no access.
 *          - The cache and the `is_readable` and `is_writable` predicates answer protection questions for one-shot
 *            setup validation and diagnostics, not for per-frame hot paths. Each consults a lock and, on a miss, can
 *            walk the range one `VirtualQuery` per region.
 *          - `unchecked::read` performs NO validation and FAULTS THE HOST on an unreadable byte.
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
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace DetourModKit
{
    namespace detail
    {
        /**
         * @brief Trait that is true for any non-owning view type: a `std::span<U, Extent>` of any element type, or a
         *        `std::basic_string_view`.
         * @details `[B-21]` A view is trivially copyable. An unconstrained typed `write<T>` / `write_in_place<T>` binds
         *          `write(addr, my_view)` exactly and stores the view's pointer and length instead of its bytes. The
         *          exclusion sends a byte span to the byte-span sink. It turns any other view into a
         *          compile error that directs the caller to `write_bytes`. Constraint sites inspect
         *          `std::remove_cvref_t<T>` so a cv/ref qualification cannot slip one past.
         */
        template <class T> inline constexpr bool is_non_owning_view_v = false;
        template <class U, std::size_t Extent> inline constexpr bool is_non_owning_view_v<std::span<U, Extent>> = true;
        template <class CharT, class Traits>
        inline constexpr bool is_non_owning_view_v<std::basic_string_view<CharT, Traits>> = true;

        /**
         * @brief Opt-in trait for aggregate types whose every object representation may be read from foreign bytes.
         * @details The default is false because C++23 cannot inspect aggregate members: a trivially copyable class may
         *          still contain `bool` or another representation-sensitive member. Specialize this trait to
         *          `std::true_type` only after verifying the complete transitive object representation, including that
         *          the type has no padding bytes whose value the caller intends to interpret. Built-in arrays are
         *          checked recursively; `std::array` opts in when its element type is representation-safe.
         * @tparam T Aggregate type to classify.
         */
        template <class T> struct enable_representation_safe_aggregate : std::false_type
        {
        };

        /// True when @p T explicitly opts into representation-safe aggregate reads.
        template <class T>
        inline constexpr bool enable_representation_safe_aggregate_v =
            enable_representation_safe_aggregate<std::remove_cv_t<T>>::value;

        /**
         * @brief True when @p E is an enumeration with a fixed underlying type.
         * @details [dcl.enum]/8 gives such an enumeration the value range of its underlying type, so every bit pattern
         *          of that type is a valid enumerator value. Direct-list-initialization from the underlying type is
         *          well-formed only for the fixed case, which is the detection this concept uses.
         */
        template <class E>
        concept fixed_underlying_enum = std::is_enum_v<E> && requires { E{std::underlying_type_t<E>{}}; };

        /**
         * @brief True when @p F is a binary floating-point type whose object representation carries no padding bits.
         * @details Padding bits have no defined value, so a foreign byte pattern read into such a type is not
         *          necessarily a valid object representation. The bit-count test is required because `is_iec559` alone
         *          is not enough: MinGW's 16-byte x87 `long double` reports `is_iec559` for an 80-bit format.
         */
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
                // The underlying type must itself qualify: `enum class E : bool` has a fixed base, yet [dcl.enum]/8
                // gives it only bool's two values, so a foreign 0x02 is no more valid as an E than as a bool.
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
         * @brief True when every bit pattern of @p T's object representation is a valid value, so forming @p T from
         *        arbitrary foreign bytes with `std::bit_cast` is well defined.
         * @details The participation gate for the raw typed reads (@ref memory::read, @ref memory::unchecked::read, and
         *          the engine's `detail::guarded_read`). The domain is an explicit allowlist, not "every scalar":
         *          - every integral type except `bool`;
         *          - a binary floating-point type with no padding bits (@ref padding_free_binary_float), which admits
         *            `float` and `double` on both toolchains and `long double` only on MSVC, where it is `double`;
         *          - an enumeration with a fixed underlying type (@ref fixed_underlying_enum) that is itself in the
         *            domain, which admits every scoped enumeration over an integer and `std::byte`;
         *          - an object or function pointer, as a Windows x64 ABI concession, not a portable C++ theorem. The
         *            result does NOT recover pointer provenance, so treat it as an address to screen with
         *            @ref memory::is_plausible_ptr and read through a guarded route, never as a pointer to
         *            dereference.
         *          - a bounded built-in array or `std::array` whose element type qualifies, recursively;
         *          - @ref Address, and any other class or union explicitly opted in through
         *            @ref enable_representation_safe_aggregate.
         *
         *          Rejected: `bool`, because a foreign byte such as `0x02` is not a valid `bool` object
         *          representation and the bit-cast is undefined behavior before a `Result` can report it. Decode it
         *          with @ref memory::read_bool. Also rejected: `std::nullptr_t`; member-object and member-function
         *          pointers, whose representations are implementation-defined multi-field structures; an unscoped
         *          enumeration with no fixed base; an enumeration over `bool`; an unbounded array; and a
         *          floating-point format with padding bits, such as MinGW's 16-byte x87 `long double`. Use
         *          @ref memory::read_into to copy any of these as raw bytes and decode them yourself.
         *
         *          Enum DOMAIN validity is a separate concern: a fixed-underlying enumeration's bit patterns are all
         *          valid representations even when a specific value is semantically invalid for an API.
         */
        template <class T> inline constexpr bool is_representation_safe_v = representation_safe<T>();
    } // namespace detail

    namespace memory
    {
        /**
         * @brief Inclusive lower bound of the canonical x64 user-mode address window.
         * @details The low 64 KiB is the reserved null-dereference region, so any value below this bound cannot be a
         *          valid object pointer.
         */
        inline constexpr std::uintptr_t USERSPACE_PTR_MIN = 0x10000;

        /**
         * @brief Exclusive upper bound of the canonical x64 user-mode address window.
         * @details Mapped user addresses sit below the 47-bit canonical split, so a value at or above this bound is a
         *          kernel-range or non-canonical address.
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
         * @details Rejects obviously bad values (null, small enum-shaped integers, non-canonical addresses) before a
         *          guarded read pays for a fault. It does NOT prove the pointer is mapped or that the target object is
         *          the expected type. Pair it with @ref module_of and a guarded @ref read for full validation.
         * @note Callback-safe: pure `constexpr` arithmetic with no memory access, lock, or syscall.
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
         * @return An empty `Result` on full success; `ErrorCode::OverlappingRanges` when @p out intersects the source
         *         range (see @ref ErrorCode::OverlappingRanges; nothing is read); otherwise `ErrorCode::ReadFaulted` on
         *         any fault or rejected argument, with the faulting byte's address in `Error::detail` - a byte inside
         *         the requested source span `[address, address + out.size())`, not inside the destination @p out. It is
         *         the first unreadable byte for the small spans a typed @ref read issues; for a span wide enough that
         *         the platform's `memcpy` touches bytes out of order it can be a later byte of the same unreadable
         *         region. A span rejected before any access, and the MinGW fallback that validates through
         *         `VirtualQuery` instead of faulting, have no faulting byte to name and report @p address instead.
         * @details The byte-level read primitive every typed @ref read forwards to. The copy runs under the engine's
         *          fault guard, so it reports a fault anywhere in the span without host termination. The function
         *          rejects an address below @ref USERSPACE_PTR_MIN. It also rejects a span whose end wraps the address
         *          space or passes @ref USERSPACE_PTR_MAX. The rejection prevents a first-chance exception from a stale
         *          or sentinel pointer. On failure the contents of @p out are unspecified.
         * @note Callback-safe: allocates nothing, takes no lock, and on the established hot path issues no syscall.
         */
        [[nodiscard]] Result<void> read_into(Address address, std::span<std::byte> out) noexcept;

        /**
         * @brief Guarded typed read of a representation-safe @p T at @p address.
         * @tparam T A trivially copyable type in the representation-safe domain
         *           (@ref detail::is_representation_safe_v, which enumerates what participates and what does not). It
         *           need not be default constructible: the bytes are read into untyped storage and reinterpreted with
         *           `std::bit_cast`, so no @p T object is constructed on the failure path. A type outside the domain is
         *           a compile error, not a runtime risk; decode `bool` through @ref read_bool and anything else through
         *           raw bytes with @ref read_into.
         * @param address Source address.
         * @return The value on success, or the propagated @ref read_into error on a read fault. A top-level bounded
         *         built-in array is returned as the equivalent nested `std::array`, because C++ functions cannot return
         *         a built-in array by value.
         * @details Forwards to @ref read_into so the `__try` frame stays in the engine TU. On success, the read
         *          collapses to a single guarded copy of `sizeof(T)` bytes followed by a no-op bit_cast.
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
         * @brief Guarded checked decode of a single foreign byte into a `bool`.
         * @param address Source address of the byte.
         * @return `false`/`true` for a byte of `0`/`1`; `ErrorCode::ReadFaulted` (faulting address in `Error::detail`)
         *         on a read fault, or `ErrorCode::InvalidRepresentation` (source address in `Error::detail`) for any
         *         other byte value.
         * @details The representation-safe route for `bool`, which the raw typed @ref read excludes: it reads one byte
         *          through the fault guard and validates it before forming the `bool`, so an arbitrary foreign byte can
         *          never be bit-cast into an invalid `bool`. Extend this checked-decoder pattern for any other
         *          representation-sensitive type a caller needs.
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<bool> read_bool(Address address) noexcept;

        /**
         * @brief Guarded write of a byte span to @p address, changing page protection only if it must.
         * @param address Destination address.
         * @param source Source byte span. An empty span is a successful no-op, but the null-target check runs
         *               first: a null @p address fails with `NullTargetAddress` even for an empty span.
         * @return An empty `Result` on success; one of `ErrorCode::NullTargetAddress`, `NullSourceBytes`,
         *         `SizeTooLarge` (over @ref MAX_WRITE_SIZE), `OverlappingRanges` (@p source intersects the target
         *         range; nothing is written), `ProtectionChangeFailed`, `WriteFaulted` (nothing was written),
         *         `WriteMayBePartial` (the changed prefix is indeterminate, as @ref ErrorCode::WriteMayBePartial
         *         defines),
         *         `InstructionFlushFailed`, or `ProtectionRestoreFailed`.
         * @details The escalating DATA write. @ref patch_code is the route for bytes that are executed. It first
         *          attempts a guarded write that changes NO page protection, so a target that is already writable
         *          costs no `VirtualProtect` and no instruction-cache flush. Only a fault on that attempt takes the
         *          slow path: change protection to writable per region, so a data page never gains execute, copy,
         *          flush the instruction cache for an executable region, restore the original protection, and
         *          invalidate the affected cache range. A @ref ProtectGuard held over a hot region therefore keeps
         *          the writes inside it on the cheap path. The slow-path copy also runs under the fault guard. A page
         *          reprotected or unmapped mid-copy returns `WriteMayBePartial`, and the restore and flush still run,
         *          with `ProtectionRestoreFailed` taking priority. A successful already-writable fast path issues no
         *          flush. A fast path that faults after it changed a prefix of an EXECUTABLE target is flushed before
         *          the fallback runs, so a protection-setup failure cannot leave modified code unflushed.
         * @note A slow-path write that straddles a protection seam is handled per region: each VirtualQuery region the
         *       span covers is unprotected and restored to its own prior protection, so patching across a .rdata/.text
         *       boundary never flattens the executable region to PAGE_READONLY. A span crossing an unrealistically
         *       large number of distinct protection regions fails closed with `ProtectionChangeFailed`.
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
         * @note Constrained against any non-owning view. A view argument is a compile error instead of a silent
         *       bit-copy of the view object. @ref detail::is_non_owning_view_v owns the rationale.
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
         * @param address Destination code address.
         * @param source Bytes to write. Empty-span and null-target rules match @ref write_bytes.
         * @return An empty `Result` on success; `NullTargetAddress` / `NullSourceBytes` / `SizeTooLarge` /
         *         `OverlappingRanges` (@p source intersects the target range) for a rejected argument,
         *         `ProtectionChangeFailed`, `WriteFaulted` (nothing was written), `WriteMayBePartial` (the changed
         *         prefix is indeterminate, as @ref ErrorCode::WriteMayBePartial defines), `ProtectionRestoreFailed`, or
         *         `InstructionFlushFailed` (the bytes landed but the flush failed).
         * @details Use this route whenever the target bytes are executed as code. Every path that may modify the target
         *          checks an instruction-cache flush, including already-writable code and a partial guarded prefix. A
         *          covering flush for a partial prefix uses the full requested range before protection-changing
         *          fallback setup. Read-only targets are made writable without adding execute to data pages, then
         *          written, flushed, restored, and invalidated in the protection cache. Use @ref write_bytes or
         *          @ref write_in_place for data.
         * @warning The write is not atomic.
         *          A copy that can have changed a prefix receives a full-range flush. A later retry that writes nothing
         *          cannot downgrade `WriteMayBePartial` to `WriteFaulted`.
         *          Restoration failure outranks partial-write status, which outranks a flush-only failure.
         * @note Callback-safe on the fast path; the protection-changing slow path is setup/control-plane work.
         */
        [[nodiscard]] Result<void> patch_code(Address address, std::span<const std::byte> source) noexcept;

        /**
         * @brief Strict guarded write of a byte span that NEVER changes page protection.
         * @param address Destination address.
         * @param source Source byte span. Empty-span and null-target rules match @ref write_bytes.
         * @return An empty `Result` on success; `ErrorCode::NullTargetAddress` / `NullSourceBytes` / `SizeTooLarge`
         *         (over @ref MAX_WRITE_SIZE) / `OverlappingRanges` (@p source intersects the target range) for a
         *         rejected argument; `ErrorCode::WriteFaulted` when the target's first byte was not writable and
         *         nothing was written; or `ErrorCode::WriteMayBePartial` when a byte further in the span faulted after
         *         the copy reached a writable page.
         * @warning Not atomic across a writability seam. When @p source straddles a writable page and an adjacent
         *          unwritable one, the copy faults and returns `ErrorCode::WriteMayBePartial`, whose changed prefix is
         *          indeterminate and can be empty. Size a per-frame store so it cannot straddle a protection boundary,
         *          or treat a `WriteMayBePartial` target as indeterminate; a `WriteFaulted` return, by contrast,
         *          guarantees that no byte changed.
         * @details The counterpart to @ref write_bytes for memory the target already keeps writable. It does NOT
         *          escalate: a read-only, executable, or no-access target fails closed with `WriteFaulted` instead of
         *          an unprotect and a write. Use it to keep a per-frame store off the `VirtualProtect` path, or to
         *          make a stale pointer that lands in read-only memory surface as an error. For a one-shot code patch
         *          use @ref patch_code.
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
         * @details Forwards to @ref write_in_place, so the same no-reprotect, fail-closed-if-not-writable contract and
         *          seam warning apply. This is the typed per-frame store.
         * @note Constrained against any non-owning view. A mutable `std::span<std::byte>` routes to the byte-span
         *       overload above. Any other view is a compile error instead of a silent bit-copy of the view object.
         *       @ref detail::is_non_owning_view_v owns the rationale.
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
         *         intermediate dereference faults or yields a link below that hop's @ref ChainStep::min_valid, or when
         *         the final leaf's signed-offset arithmetic wraps or lands outside [@ref USERSPACE_PTR_MIN,
         *         @ref USERSPACE_PTR_MAX).
         * @details The walk gates each hop, captures each intermediate link, and exits at the first bad hop. It does
         *          not dereference the returned leaf, but it screens the leaf into
         *          [@ref USERSPACE_PTR_MIN, @ref USERSPACE_PTR_MAX) like every intermediate link, so a wrapped or
         *          non-canonical result reports a failure instead of a plausible success. The caller reads the leaf,
         *          usually through @ref read.
         * @note Callback-safe (see @ref read_into).
         */
        [[nodiscard]] Result<Address>
        walk(Address base, std::span<const ChainStep> steps, std::span<Address> trace = {}) noexcept;

        /**
         * @brief Convenience @ref walk taking bare offsets, flooring every hop at @ref USERSPACE_PTR_MIN.
         * @param base Root address of the chain.
         * @param offsets Byte offsets applied left to right (see the @ref ChainStep overload for the hop semantics).
         *        Capped at 32 hops. Past the cap the call fails with @ref ErrorCode::SizeTooLarge (see the @note).
         * @param trace Optional intermediate-capture buffer (see the @ref ChainStep overload).
         * @return The resolved leaf address, or the same errors as the @ref ChainStep overload, plus
         *         `ErrorCode::SizeTooLarge` when @p offsets exceeds the 32-hop inline bound.
         * @details The common chain shape carries no per-hop floor, so this overload accepts a plain `{0x18, 0x40}`
         *          offset list and applies the default plausibility floor to each dereferenced link. It is exactly the
         *          @ref ChainStep overload with every `min_valid` defaulted.
         * @note Callback-safe (see @ref read_into): it builds the step list on a fixed 32-entry stack buffer and never
         *       allocates. A chain longer than 32 hops therefore fails closed with `ErrorCode::SizeTooLarge`. Route
         *       such a chain through the @ref ChainStep overload, whose caller owns the step storage.
         */
        [[nodiscard]] Result<Address>
        walk(Address base, std::span<const std::ptrdiff_t> offsets, std::span<Address> trace = {}) noexcept;

        /**
         * @class ProtectGuard
         * @brief Move-only RAII page-protection change: applies a @ref Prot to a @ref Region and restores it on scope
         *        exit.
         * @details Built only through @ref make, so a guard cannot exist without a successful protection change to
         *          unwind. Hold one over a region that is patched or written repeatedly. If the applied @ref Prot
         *          includes @ref Prot::W, every @ref write_bytes inside the guarded window uses the cheap no-reprotect
         *          fast path. Destructor restoration is best-effort. To observe the restore result, call @ref restore
         *          before the guard dies.
         * @note The guard captures each VirtualQuery region's own prior protection across the span and restores every
         *       region to its own value, so a guard laid over a .rdata/.text seam does not flatten the executable
         *       region to PAGE_READONLY on restore. A span that crosses an unrealistically large number of distinct
         *       protection regions fails closed at @ref make instead of a partially-changed span.
         * @note Every protection-restoring path invalidates the cached span: @ref make, the destructor, and
         *       move-assignment (which restores the replaced guard's own region before adopting the source) each call
         *       @ref invalidate_range, so the protection cache never answers a later @ref is_readable /
         *       @ref is_writable from a snapshot taken before the guard changed (or restored) the protection.
         */
        class ProtectGuard
        {
        public:
            /**
             * @brief Changes @p region to @p protection and returns a guard that restores the prior protection.
             * @param region The span whose protection is changed; an empty region fails closed. It may cross protection
             *               seams: each region within it is captured and restored separately (see the class notes).
             * @param protection The protection to apply for the guard's lifetime.
             * @return An armed guard on success; `ErrorCode::OutOfMemory` if the guard's capture state could not be
             *         allocated (no protection change is attempted, so nothing leaks);
             *         `ErrorCode::ProtectionChangeFailed` (with the OS error in `Error::extra`) if the protection could
             *         not be changed for a region, or the span crosses more distinct protection regions than the guard
             *         can track, in which case any region already changed is rolled back before returning; or
             *         `ErrorCode::ProtectionRestoreFailed` if that rollback itself failed, leaving a region in a
             *         transient protection.
             * @details The capture state is allocated before any protection is changed, so a failed allocation cannot
             *          strand the region in the new protection with no guard to restore it. On success the changed
             *          range is dropped from the protection cache (@ref invalidate_range).
             * @note Setup/control-plane only: the guard allocates and issues VirtualProtect syscalls.
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

            /**
             * @brief Disarms the guard. Its destructor then leaves the changed protection in place.
             * @details The page entry leaves the ledger once no other guard holds that page, so the next guard over
             *          it captures the current protection. While another guard still holds the page, this guard's
             *          applied protection becomes that guard's restore baseline.
             * @note Setup/control-plane only: ledger removal takes the protection ledger lock.
             */
            void release() noexcept;

            /**
             * @brief Restores the original protection now, reports the result, and disarms the guard.
             * @return An empty `Result` on success; `ErrorCode::ProtectionRestoreFailed` (OS error in `Error::extra`)
             *         when a region could not be restored. A moved-from, released, or already-restored guard returns
             *         success. There is nothing left to restore.
             * @details The observable counterpart to the best-effort destructor. Idempotent: it disarms the guard, so
             *          the destructor then does nothing. On failure the guard is still disarmed, and the range is
             *          dropped from the protection cache exactly as the destructor does.
             * @note Setup/control-plane only: the restore issues VirtualProtect syscalls.
             */
            [[nodiscard]] Result<void> restore() noexcept;

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
         * @details Every call reports the extent the image currently publishes, so a module replaced at the same
         *          base is never answered from the previous image's headers.
         * @note Setup/control-plane only: the call issues a loader lookup and a guarded PE-header read.
         * @warning The returned Region is a non-owning scope. It does not pin the module, so a module unloaded after
         *          this returns leaves a span that references freed address space.
         */
        [[nodiscard]] Region module_of(Address address) noexcept;

        /**
         * @brief Reports whether a module with the given base name is currently loaded in the process.
         * @param basename The module's file name as the loader knows it (e.g. "kernel32.dll"); a bare name, not a path.
         * @param case_insensitive When true (the default, matching Windows module-name semantics) the comparison
         *                         ignores case.
         * @return True when a loaded module's base name matches @p basename.
         *         A path longer than `MAX_PATH` does not change either answer.
         * @note Setup/control-plane only: the query reaches the loader. An exact-case request fails closed under the
         *       loader lock, because it requires a counted module reference.
         */
        [[nodiscard]] bool is_module_loaded(std::string_view basename, bool case_insensitive = true) noexcept;

        /**
         * @struct MemoryStats
         * @brief Allocation-free snapshot of protection-cache configuration and counters.
         * @details Every field mirrors a value reported by @ref get_cache_stats. Counters are loaded with relaxed
         *          atomics and the live-entry totals are summed under the shard reader guard, so the struct is a
         *          consistent-per-field but not globally-atomic view. @ref hit_rate_percent is -1.0 when no queries
         *          have been tracked (hits + misses == 0).
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
            /**
             * @brief Sticky count of lifecycle-invariant violations recovered without terminating.
             * @details Includes an unexpected joinable handle before start and any contained join/detach failure.
             *          Monotonic; never reset by clear or shutdown, and expected to remain zero in normal operation.
             */
            std::uint64_t lifecycle_violations = 0;
        };

        /**
         * @brief Initializes the protection-region cache used by @ref is_readable / @ref is_writable.
         * @param cache_size Desired number of entries across the cache.
         * @param expiry_ms Cache entry expiry time in milliseconds.
         * @param shard_count Number of cache shards for concurrent access.
         * @return True if the cache is ready for use.
         *         False if lifecycle state blocks a start or cache setup fails.
         *         A false return leaves the cache stopped, so readers use the uncached `VirtualQuery` route.
         * @details A call while the cache is running returns true and keeps the running configuration, with no
         *          reconfiguration and no loader-lock check.
         *          A call after @ref shutdown_cache starts a fresh cache with the arguments of that call. A start fails
         *          if readers from a prior session do not exit before the drain deadline. It retains that session's
         *          storage and precommitted module reference.
         *          A successful start creates the cleanup thread when the platform permits it.
         *          Otherwise, the cache uses on-demand cleanup.
         *          MinGW also installs the process fault handler for guarded reads.
         * @note Setup/control-plane only. Every cache setup failure appears in the return value.
         */
        [[nodiscard]] bool init_cache(
            std::size_t cache_size = DEFAULT_CACHE_SIZE,
            unsigned int expiry_ms = DEFAULT_CACHE_EXPIRY_MS,
            std::size_t shard_count = DEFAULT_CACHE_SHARD_COUNT
        );

        /**
         * @brief Clears all entries from the protection cache, leaving it initialized.
         * @details Invalidates all cached region information; the background cleanup thread keeps running.
         * @note Setup/control-plane only: the clear takes every shard's exclusive lock.
         */
        void clear_cache() noexcept;

        /**
         * @brief Shuts the cache down and joins the background cleanup thread.
         * @details Call before module unload to terminate the cleanup thread cleanly. After shutdown, the cache cannot
         *          be reused without re-initialization. Under loader lock the thread is detached rather than joined to
         *          avoid deadlock, and on MinGW the vectored fault handler is drained and removed.
         *          Teardown closes reader admission first. A later permission query takes the uncached `VirtualQuery`
         *          route. The wait for admitted readers has a fixed deadline. The cache precommits a module reference
         *          before admission opens. On expiry it retains that reference and the cache storage. It also records
         *          one @ref diagnostics::LeakSubsystem::MemoryCache event. A later @ref init_cache or
         *          @ref shutdown_cache call can reclaim the storage after the stalled reader exits. A clean shutdown
         *          releases the cache reference.
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
         * @note Setup/control-plane only: the invalidation mutates the cache shards.
         */
        void invalidate_range(Region range) noexcept;

        /**
         * @enum ReadableStatus
         * @brief Tri-state result for the non-blocking readability check.
         */
        enum class ReadableStatus : std::uint8_t
        {
            /// The region is committed and readable.
            Readable,
            /// The region is not committed, not readable, or the arguments were rejected.
            NotReadable,
            /**
             * @brief Reports that a wait is required before the check can produce a result.
             * @details This value arises only while the cache runs, in these cases:
             *          - The shard lock is contended.
             *          - The cache misses.
             *          - A concurrent shutdown unpublished the shards.
             */
            Unknown
        };

        /**
         * @brief Reports whether @p range is committed and readable.
         * @param range The span to check. An empty range returns false.
         * @return True when the entire range is readable and committed.
         * @warning On a per-dereference hot path, do not use this function. A hit takes a shard reader lock. A miss can
         *          walk the range's regions with one VirtualQuery per region. The answer is a time-of-check/time-of-use
         *          snapshot. For hot game-owned reads, a guarded @ref read provides a checked `Result`. An optional
         *          @ref is_plausible_ptr call can pre-screen the address.
         * @note Setup/control-plane only: see the hot-path warning above; a latency-sensitive caller uses
         *       @ref is_readable_nonblocking.
         */
        [[nodiscard]] bool is_readable(Region range) noexcept;

        /**
         * @brief Reports whether @p range is committed and writable.
         * @param range The span to check. An empty range returns false.
         * @return True when the entire range is writable and committed.
         * @warning Carries the same hot-path cost and time-of-check/time-of-use caveat as @ref is_readable; reserve it
         *          for one-shot setup validation. To write, prefer attempting a guarded @ref write_bytes which fails
         *          closed.
         * @note Setup/control-plane only (see @ref is_readable).
         */
        [[nodiscard]] bool is_writable(Region range) noexcept;

        /**
         * @brief Non-blocking readability check that returns @ref ReadableStatus::Unknown rather than stalling.
         * @param range The span to check. An empty range returns @ref ReadableStatus::NotReadable.
         * @return @ref ReadableStatus::Readable / NotReadable for a definite answer, or @ref ReadableStatus::Unknown
         *         when answering would require blocking (a contended shard try-lock or a cache miss, while the cache
         *         runs), so a latency-sensitive caller can fall back to a guarded @ref read instead of stalling.
         * @details While the cache is not in its running state (before @ref init_cache, during initialization or
         *          shutdown, or after @ref shutdown_cache), there is no cache to consult. The check then falls back
         *          to a blocking range walk with one VirtualQuery per region and returns a definite answer, never
         *          Unknown.
         * @note Callback-safe while the cache runs: a try-lock probe with no allocation. Outside the running state it
         *       takes the blocking fallback above.
         */
        [[nodiscard]] ReadableStatus is_readable_nonblocking(Region range) noexcept;

        /**
         * @namespace DetourModKit::memory::unchecked
         * @brief The raw, validation-free fast path. Every entry point here FAULTS THE HOST on an unreadable byte.
         * @details Quarantined in its own namespace so the danger is visible at the call site: nothing here guards,
         *          gates, or reports an error, because the contract is "the caller has already proven this access is
         *          safe".
         */
        namespace unchecked
        {
            /**
             * @brief Unguarded typed read of a representation-safe @p T at @p address.
             * @tparam T A trivially copyable type in the representation-safe domain
             *           (@ref detail::is_representation_safe_v), the same gate the guarded @ref read applies. This
             *           route has no error channel at all, so the domain is enforced purely at compile time; decode
             *           `bool` through the guarded @ref read_bool.
             * @param address Source address. EVERY byte of `[address, address + sizeof(T))` MUST be committed and
             *                 readable; this performs NO validation and a violation faults the host process.
             * @return The value at @p address. A top-level bounded built-in array is returned as the equivalent nested
             *         `std::array`, because C++ functions cannot return a built-in array by value.
             * @details A single inlined copy with no SEH, no VirtualQuery, and no cache lookup. Use it only for
             *          pointers that the caller proves are live for the current frame. For anything that can be stale,
             *          use the guarded @ref read.
             * @note Callback-safe by construction (it does nothing but copy), but UNSAFE on an invalid address.
             * @note An `assert(is_readable(...))` trips a violated precondition in a Debug build. It is compiled out
             *       under NDEBUG, so a Release build has NO diagnostic and an invalid address faults the host.
             */
            template <class T>
                requires(std::is_trivially_copyable_v<T> && detail::is_representation_safe_v<T>)
            [[nodiscard]] detail::representation_read_value_t<T> read(Address address) noexcept
            {
                // The is_readable() probe must not survive into Release. assert() discards it under NDEBUG.
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
