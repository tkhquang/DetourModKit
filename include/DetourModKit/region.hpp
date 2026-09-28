#ifndef DETOURMODKIT_REGION_HPP
#define DETOURMODKIT_REGION_HPP

/**
 * @file region.hpp
 * @brief The Region value type and the Prot protection flags, the shared range-of-memory vocabulary.
 * @details Of all Region operations, only `module_named()` can allocate.
 * @warning `[B-100]` `host()`, `own()`, and `module_named()` query loader state. Never call them under the Windows
 *          loader lock, for example from a namespace-scope static initializer in a DLL. `whole_process()` does not
 *          query loader state. `RegionLoaderBoundary.*` pins this boundary.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/defines.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit
{
    /** @brief A half-open span [base, base + size) with no invariant. A failed factory returns `Region{}`. */
    struct Region
    {
        /// Inclusive start of the span.
        Address base{};
        /// Length of the span in bytes. A zero size denotes an empty Region.
        std::size_t size{0};

        /// Returns the exclusive end address.
        [[nodiscard]] constexpr Address end() const noexcept { return base.offset(static_cast<std::ptrdiff_t>(size)); }

        /** @brief Tests whether base <= @p address < end(). An empty Region contains no address. */
        [[nodiscard]] constexpr bool contains(Address address) const noexcept
        {
            return address >= base && address < end();
        }

        /** @brief Returns [base + @p offset, base + @p offset + @p length), unclamped. Keep it inside this Region. */
        [[nodiscard]] constexpr Region sub(std::size_t offset, std::size_t length) const noexcept
        {
            return Region{base.offset(static_cast<std::ptrdiff_t>(offset)), length};
        }

        /**
         * @brief Returns the image span of the host process EXE, or an empty Region if it cannot be resolved.
         * @note Setup/control-plane only. See the file `[B-100]` loader-lock warning.
         */
        [[nodiscard]] static Region host() noexcept;

        /**
         * @brief Returns the image span of the DLL or EXE that linked DetourModKit, or an empty Region on failure.
         * @note Setup/control-plane only. See the file `[B-100]` loader-lock warning.
         */
        [[nodiscard]] static Region own() noexcept;

        /**
         * @brief Returns the image span of loaded module @p name, or an empty Region for an empty, invalid, or unloaded
         *        name or a failed allocation.
         * @param name UTF-8 module name as the loader knows it, for example "kernel32.dll".
         * @note Setup/control-plane only. See the file `[B-100]` loader-lock warning.
         */
        [[nodiscard]] static Region module_named(std::string_view name) noexcept;

        /**
         * @brief Returns the span from the system minimum application address through the maximum, inclusive.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] static Region whole_process() noexcept;
    };

    /** @brief Backend-neutral page protection as composable read, write, and execute flags. */
    enum class Prot : std::uint32_t
    {
        None = 0,
        R = 1,
        W = 2,
        X = 4,
        RW = R | W,
        RWX = R | W | X
    };

    DMK_FLAG_ENUM(Prot)

} // namespace DetourModKit

#endif // DETOURMODKIT_REGION_HPP
