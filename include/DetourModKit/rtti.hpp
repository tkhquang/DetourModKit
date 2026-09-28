#ifndef DETOURMODKIT_RTTI_HPP
#define DETOURMODKIT_RTTI_HPP

#include "DetourModKit/region.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace DetourModKit
{
    /**
     * @brief MSVC RTTI introspection primitives for x64 MSVC binaries.
     * @details Works on raw addresses across DLL boundaries. An unreadable page, an absent or malformed COL, or a zero
     *          RVA returns a failure. A guarded read whose guard-page re-arm fails (`[B-20]`) passes its fault to the
     *          host. Names are mangled, for example ".?AVMyClass@ns@@", and compare byte-exact.
     *
     *          In a /GR- host, every resolver fails closed. The raw-byte fallbacks are @ref scan::find_string_xref and
     *          @ref scan::read_code_constant. See docs/guides/rtti/rtti-walker.md.
     * @warning `[B-100]` Under the loader lock, call @ref TypeIdentity::matches only after it is warm, or use another
     *          Callback-safe entry point. Cold identity paths and setup routes can query the loader or sweep an image.
     */
    namespace rtti
    {
        /// Default cap on the mangled-name length read into a heap-allocated string.
        inline constexpr std::size_t DEFAULT_TYPE_NAME_MAX = 256;

        /// Hard upper bound on any single mangled-name read.
        inline constexpr std::size_t MAX_TYPE_NAME_LEN = 1024;

        /** @brief Completeness of a reverse-RTTI sweep. Only @ref Complete authorizes a unique or absent verdict. */
        enum class Traversal : std::uint8_t
        {
            /// Every eligible section was enumerated, and every page in it was read.
            Complete = 0,
            /** @brief The sweep under-covered the image. */
            Incomplete = 1,
            /** @brief The internal fixed buffer filled, so unseen sections or matches can exist. */
            Saturated = 2
        };

        /** @brief Outcome of a checked mangled-name read (@ref type_name_checked). */
        enum class NameStatus : std::uint8_t
        {
            /// The full NUL-terminated name was copied.
            Ok = 0,
            /** @brief The NUL-terminated copy is a proper prefix and must not be compared for identity. */
            Truncated = 1,
            /// No name was read (null or low vtable, absent or malformed COL, unreadable page).
            Failed = 2
        };

        /** @brief Result of @ref type_name_checked. */
        struct NameRead
        {
            /// Name bytes written, without the NUL terminator.
            std::size_t written = 0;
            /// Whether the copy is complete, a truncated prefix, or a failure.
            NameStatus status = NameStatus::Failed;
        };

        /** @brief Result of @ref vtables_for_type_checked. */
        struct VtablesResult
        {
            /// Distinct sub-object vtables that match (the same value @ref vtables_for_type returns).
            std::size_t count = 0;
            /** @brief Sweep completeness. Under Incomplete or Saturated, @ref count is only a floor. */
            Traversal completeness = Traversal::Complete;
        };

        /** @brief Answer of @ref region_rtti_presence, with an absence distinct from an incomplete sweep. */
        enum class RttiPresence : std::uint8_t
        {
            /// At least one resolvable RTTI record was found. A hit is sound regardless of completeness.
            Present = 0,
            /// The sweep completed and found no record: an authoritative absence (an MSVC /GR- scope, a data module).
            Absent = 1,
            /** @brief The sweep did not complete, so absence cannot be concluded. */
            Incomplete = 2
        };

        /**
         * @brief Reads the MSVC RTTI mangled type-descriptor name for the object whose runtime vtable is at @p vtable.
         * @param max_len Maximum name length to copy, clamped to @ref MAX_TYPE_NAME_LEN. Zero means
         *                @ref DEFAULT_TYPE_NAME_MAX. A longer name comes back as a truncated prefix. If truncation
         *                matters, use @ref type_name_checked.
         * @return The mangled name, or std::nullopt on any read or allocation failure or for an empty name.
         * @note Setup/control-plane only: the call makes one heap allocation and queries the loader.
         */
        [[nodiscard]] std::optional<std::string>
        type_name_of(Address vtable, std::size_t max_len = DEFAULT_TYPE_NAME_MAX) noexcept;

        /**
         * @brief Zero-allocation form of @ref type_name_of.
         * @param out Destination buffer, NUL-terminated when @p out_len > 0. On failure its first byte is '\0'. Must
         *            be non-null when @p out_len > 0.
         * @param out_len Capacity of @p out, NUL terminator included. The call writes at most @p out_len bytes.
         * @return Name bytes written without the NUL terminator, or 0 on failure or empty output.
         * @note Setup/control-plane only: each call runs the COL prelude, which queries the loader. Cache a
         *       @ref TypeIdentity for a per-frame check.
         */
        [[nodiscard]] std::size_t type_name_into(Address vtable, char *out, std::size_t out_len) noexcept;

        /**
         * @brief Truncation-reporting form of @ref type_name_into, with the same buffer contract.
         * @return The name bytes written and the status. @ref NameStatus::Truncated means that @p out holds only a
         *         prefix. The name did not fit @p out or the @ref MAX_TYPE_NAME_LEN cap, or it has no readable
         *         terminator inside its module. @ref NameStatus::Failed leaves @p out empty.
         * @note Setup/control-plane only (see @ref type_name_into).
         */
        [[nodiscard]] NameRead type_name_checked(Address vtable, char *out, std::size_t out_len) noexcept;

        /**
         * @brief A stable, mapping-scoped identity token for the module currently mapped over @p addr.
         * @details Folds the image base plus the three @ref scan::image_identity fields (SizeOfImage, PE TimeDateStamp,
         *          and the section table) into 64 bits. The token is stable while one image stays mapped. It changes
         *          when a same-base replacement changes an identity-bearing PE header field.
         * @return A nonzero token, or 0 when @p addr is not inside a loaded module or the module's PE headers do not
         *         parse.
         * @note Setup/control-plane only: it queries the loader for the module at @p addr, then reads its PE header.
         * @warning This is layout identity, not content identity. A replacement that preserves every folded header
         *          field and changes only section bytes stays invisible.
         */
        [[nodiscard]] std::uint64_t image_generation(Address addr) noexcept;

        /**
         * @brief Tests whether the MSVC RTTI mangled name for @p vtable equals @p expected exactly.
         * @details Compares the name and its NUL byte for byte, so a proper prefix or a substring does not match.
         * @param expected Must be non-empty and shorter than @ref MAX_TYPE_NAME_LEN.
         * @return true on an exact match. false on a mismatch, a read failure, or an empty or oversized @p expected.
         * @note Setup/control-plane only: each call runs the COL prelude, which queries the loader. It does not
         *       allocate. @ref TypeIdentity::matches is the per-frame route.
         */
        [[nodiscard]] bool vtable_is_type(Address vtable, std::string_view expected) noexcept;

        /**
         * @brief Generation-bearing cache for repeated @ref find_in_pointer_table calls with one expected type.
         * @details Concurrent lookups are supported, and publication does not block.
         */
        class PointerTableCache
        {
        public:
            /// Constructs an empty cache.
            PointerTableCache() noexcept = default;
            PointerTableCache(const PointerTableCache &) = delete;
            PointerTableCache &operator=(const PointerTableCache &) = delete;
            PointerTableCache(PointerTableCache &&) = delete;
            PointerTableCache &operator=(PointerTableCache &&) = delete;
            ~PointerTableCache() noexcept = default;

            /**
             * @brief Clears the cached snapshot so the next lookup starts cold.
             * @note Setup/control-plane only: waits for an in-progress cache publication to finish.
             */
            void reset() noexcept;

        private:
            friend std::optional<Address> find_in_pointer_table(
                Address table,
                std::size_t slot_count,
                std::string_view expected,
                PointerTableCache &cache,
                std::size_t stride
            ) noexcept;

            // Single-writer sequence that keeps the {vtable, image base, generation} snapshot coherent.
            std::atomic_flag m_writer{};
            std::atomic<std::uint32_t> m_seq{0};
            std::atomic<Address> m_vtable{Address{}};
            std::atomic<Address> m_image_base{Address{}};
            std::atomic<std::uint64_t> m_generation{0};
            // Advanced by reset() so a lookup that started earlier cannot publish across the reset boundary.
            std::atomic<std::uint64_t> m_epoch{0};
        };

        /**
         * @brief Scans a pointer table for the first slot whose object has the given RTTI type-descriptor name.
         * @details Treats @p table as @p slot_count slots spaced @p stride bytes apart. A cold or null cache walks RTTI
         *          per slot through @ref vtable_is_type. A warm cache compares each slot against the cached vtable. If
         *          no slot carries it, the call clears the stale value and runs one cold pass. A cold-path match
         *          refreshes the cache. A null Address means cold.
         * @param vtable_cache Optional caller-owned cache, one per expected name. Pass nullptr to walk RTTI every call.
         * @return The value stored in the first slot that matches, or std::nullopt.
         * @warning The warm path assumes one vtable per expected name and skips a match with any other vtable. A
         *          secondary-base sub-object vtable, or a vtable of the same class in another module, shares that name.
         * @warning The raw atomic carries no image generation. Clear it at module-lifecycle boundaries, or use the
         *          @ref PointerTableCache overload.
         * @note Callback-safe on the warm-cache path, which costs two guarded reads and one compare per slot. A cold or
         *       stale cache is setup/control-plane work.
         */
        [[nodiscard]] std::optional<Address> find_in_pointer_table(
            Address table,
            std::size_t slot_count,
            std::string_view expected,
            std::atomic<Address> *vtable_cache = nullptr,
            std::size_t stride = sizeof(std::uintptr_t)
        ) noexcept;

        /**
         * @brief Generation-checked overload of @ref find_in_pointer_table.
         * @details A warm call reads the image generation before and after the slot scan and accepts the snapshot only
         *          while it stays current. A stale snapshot is cleared and resolved cold.
         * @param cache Caller-owned cache, dedicated to one expected name. If the cache outlives a module unload or
         *              reload, use this overload.
         * @note Callback-safe on the warm-cache path. A cold or stale cache is setup/control-plane work.
         */
        [[nodiscard]] std::optional<Address> find_in_pointer_table(
            Address table,
            std::size_t slot_count,
            std::string_view expected,
            PointerTableCache &cache,
            std::size_t stride = sizeof(std::uintptr_t)
        ) noexcept;

        /**
         * @brief Resolves the primary (most-derived) vtable for a class by its MSVC mangled name in one module image.
         * @details Sweeps the readable, non-executable sections for the COL with name @p mangled and COL.offset 0. For
         *          a class used only as a secondary or virtual base, use @ref vtables_for_type.
         * @return The primary vtable on a unique match. std::nullopt on absence, an invalid scope, ambiguous primaries,
         *         or an incomplete sweep. @ref vtables_for_type_checked tells absence from an incomplete sweep.
         * @note Setup/control-plane only: run it once at init or behind a cached @ref TypeIdentity, never per frame.
         */
        [[nodiscard]] std::optional<Address>
        vtable_for_type(std::string_view mangled, Region range = Region::host()) noexcept;

        /**
         * @brief Collects every sub-object vtable that shares a class's mangled name.
         * @param out Receives the vtables in ascending COL.offset order, primary first. It can be nullptr only when
         *            @p out_cap is 0 (a count-only query).
         * @return Number of distinct matches, capped at an internal bound. A value above @p out_cap means @p out was
         *         truncated. After an incomplete or saturated sweep, the count is only a floor.
         *         @ref vtables_for_type_checked reports the completeness.
         * @note Setup/control-plane only (see @ref vtable_for_type).
         */
        [[nodiscard]] std::size_t vtables_for_type(
            std::string_view mangled,
            Address *out,
            std::size_t out_cap,
            Region range = Region::host()
        ) noexcept;

        /**
         * @brief Completeness-reporting form of @ref vtables_for_type, with the same parameters and count.
         * @note Setup/control-plane only (see @ref vtable_for_type).
         */
        [[nodiscard]] VtablesResult vtables_for_type_checked(
            std::string_view mangled,
            Address *out,
            std::size_t out_cap,
            Region range = Region::host()
        ) noexcept;

        /**
         * @brief Reports whether a module region currently contains any resolvable MSVC RTTI record.
         * @details A true answer proves only that some record exists, not that the caller's type resolves. A false
         *          answer means only that the swept part held no record. See @ref region_rtti_presence.
         * @return false also when @p range is not a valid mapped image.
         * @note Setup/control-plane only (see @ref vtable_for_type). It has no re-sweep throttle, so a records-free
         *       scope pays a full sweep on every call.
         * @note An absent verdict on a still-packed image describes only the current mapping, not a /GR- build. After
         *       the image unpacks, inspect again. Do not cache the result as permanent.
         */
        [[nodiscard]] bool region_has_rtti(Region range = Region::host()) noexcept;

        /**
         * @brief Completeness-reporting form of @ref region_has_rtti. An invalid @p range reports Incomplete.
         * @note Setup/control-plane only (see @ref vtable_for_type).
         */
        [[nodiscard]] RttiPresence region_rtti_presence(Region range = Region::host()) noexcept;

        /**
         * @brief Cached, self-healing, generation-aware identity handle for a class vtable.
         * @details Resolves the primary vtable lazily through @ref vtable_for_type and caches it with its image
         *          generation. The warm path checks that generation on every call and resolves again after a remap. A
         *          private-buffer scope has no module generation and must be reset explicitly through @ref invalidate.
         * @note Take identity from the cached vtable address, never from the vtable's slot contents. Under /OPT:ICF
         *       folding, two distinct classes can share function-pointer slots.
         * @note Owns a copy of its mangled name. Hold it as a static or a long-lived member.
         */
        class TypeIdentity
        {
        public:
            /**
             * @brief Constructs a cached identity for @p mangled, scoped to @p range.
             * @throws std::bad_alloc if the name copy cannot be allocated.
             * @note Setup/control-plane only: cache construction allocates.
             */
            explicit TypeIdentity(std::string_view mangled, Region range = Region::host());

            TypeIdentity(const TypeIdentity &) = delete;
            TypeIdentity &operator=(const TypeIdentity &) = delete;
            TypeIdentity(TypeIdentity &&) = delete;
            TypeIdentity &operator=(TypeIdentity &&) = delete;
            ~TypeIdentity() noexcept = default;

            /**
             * @brief Tests whether @p vtable is this type's primary vtable.
             * @details Resolves on first call, then compares. A type that cannot be resolved never matches.
             * @note Callback-safe once warm: the generation check performs bounded guarded PE-header reads. A changed
             *       image triggers a setup-cost resolve.
             */
            [[nodiscard]] bool matches(Address vtable) const noexcept;

            /**
             * @brief Returns the primary vtable, or std::nullopt when this call does not resolve it in the configured
             *        range.
             * @note Callback-safe once warm: the first call runs a setup-cost module sweep and caches a success. A miss
             *       is not cached, and an internal cooldown throttles the retry sweep. A call within that cooldown, or
             *       one that overlaps another resolve, can return std::nullopt.
             */
            [[nodiscard]] std::optional<Address> vtable() const noexcept;

            /**
             * @brief Drops the cached resolve so the next @ref vtable or @ref matches resolves again from scratch.
             * @details Idempotent and safe to call at any time, for example after its module was reloaded.
             * @note Setup/control-plane only: waits for an in-progress cache publication to finish.
             */
            void invalidate() noexcept;

        private:
            std::string m_mangled;
            Region m_range;
            bool m_tracks_module_range{false};

            // A successful resolve stores the vtable, and invalidate() or a generation change clears it. A release
            // store of m_resolved publishes m_cached.
            mutable std::atomic<Address> m_cached{Address{}};
            mutable std::atomic<bool> m_resolved{false};

            // image_generation of the resolved type's module at the last success (0 = none, or a non-module range).
            mutable std::atomic<std::uint64_t> m_image_stamp{0};
            mutable std::atomic<Address> m_image_base{Address{}};

            // Serializes the short publish/clear transaction. The RTTI sweep runs without it.
            mutable std::atomic_flag m_cache_writer{};
            // Incremented on every clear, so a resolve already in flight cannot publish afterward.
            mutable std::atomic<std::uint64_t> m_cache_epoch{0};

            // Last resolve attempt that controls a retry, in milliseconds (0 = never). A warm hit does not write it.
            mutable std::atomic<std::uint64_t> m_last_attempt_ms{0};
        };
    } // namespace rtti
} // namespace DetourModKit

#endif // DETOURMODKIT_RTTI_HPP
