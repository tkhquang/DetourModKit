#ifndef DETOURMODKIT_REGION_HPP
#define DETOURMODKIT_REGION_HPP

/**
 * @file region.hpp
 * @brief The Region value type and the Prot protection flags -- the shared "range of memory" vocabulary.
 * @details v3 threaded scan and memory scope around as loose `(base, size)` pairs and answered "which module?" with a
 *          family of name-suffixed functions (resolve_cascade_in_host_module, ..._in_named_module, ...). Region folds
 *          both into one value: a base Address plus a byte size, with the scope expressed by which named factory
 *          produced it rather than by a function-name suffix. A scan that should run over the host executable now
 *          takes `Region::host()` as an argument, so scope is data the caller can store, compare, and narrow with
 *          sub(), not a branch baked into an API name.
 */

#include "DetourModKit/address.hpp"
#include "DetourModKit/defines.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace DetourModKit
{
    /**
     * @struct Region
     * @brief A half-open span of process memory: [base, base + size).
     * @details A plain data aggregate -- it maintains no invariant beyond what its fields hold, so it stays a POD-like
     *          struct with public fields and is freely copied. An empty Region (null base, zero size) is the
     *          fail-closed result every factory returns when its scope cannot be resolved, and `contains()` reports
     *          false for any address against it.
     */
    struct Region
    {
        /// Inclusive start of the span.
        Address base{};
        /// Length of the span in bytes; a size of 0 denotes an empty Region.
        std::size_t size{0};

        /// Returns the exclusive end address (base advanced by size).
        [[nodiscard]] constexpr Address end() const noexcept { return base.offset(static_cast<std::ptrdiff_t>(size)); }

        /**
         * @brief Tests whether @p address lies within the half-open span.
         * @param address The address to test.
         * @return True when base <= address < end(); false for any address against an empty Region.
         */
        [[nodiscard]] constexpr bool contains(Address address) const noexcept
        {
            return address >= base && address < end();
        }

        /**
         * @brief Returns a sub-span starting @p offset bytes into this Region and running for @p length bytes.
         * @param offset Byte offset from base at which the sub-span starts.
         * @param length Length of the sub-span in bytes.
         * @details Pure value arithmetic with no clamping: the caller owns keeping the sub-span inside the parent,
         *          matching how it is used to carve a known-good window out of an already-validated Region.
         */
        [[nodiscard]] constexpr Region sub(std::size_t offset, std::size_t length) const noexcept
        {
            return Region{base.offset(static_cast<std::ptrdiff_t>(offset)), length};
        }

        /**
         * @brief Returns the Region spanning the host process image (the .exe the mod is injected into).
         * @return The host module's mapped image span, or an empty Region if it cannot be resolved.
         * @details This is the default scope for a cascade that carries no explicit range: a mod overwhelmingly scans
         *          the game executable it was injected into.
         * @note Setup/control-plane only -- queries the loader; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] static Region host() noexcept;

        /**
         * @brief Returns the Region spanning a named, already-loaded module.
         * @param name UTF-8 module name as the loader knows it (e.g. "kernel32.dll").
         * @return The module's mapped image span, or an empty Region if @p name is empty or the module is not loaded.
         * @note Setup/control-plane only -- queries the loader; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] static Region module_named(std::string_view name) noexcept;

        /**
         * @brief Returns the Region spanning this process's entire user-mode address window.
         * @return The span from the system minimum to maximum application address.
         * @details The widest scope, for a scan that cannot assume which module holds the target. It reflects the
         *          system's reported application-address window rather than a hardcoded ceiling, so it stays correct
         *          across address-layout differences.
         * @note Setup/control-plane only; a whole-process scan is a startup-time operation, never a per-frame one.
         */
        [[nodiscard]] static Region whole_process() noexcept;
    };

    /**
     * @enum Prot
     * @brief Page protection as composable read/write/execute flags.
     * @details A backend-neutral spelling of memory protection: the scan and memory layers speak in `Prot::RW` rather
     *          than the platform's `PAGE_READWRITE` constants, so the public surface never leaks an OS protection
     *          value. The RW / RWX combinations are predefined for the common cases; arbitrary unions compose through
     *          the flag operators generated below.
     */
    enum class Prot : std::uint32_t
    {
        None = 0,
        R = 1,
        W = 2,
        X = 4,
        RW = R | W,
        RWX = R | W | X
    };

    // Emit Prot's bitwise/compound operators in this namespace (unqualified enum), so `Prot::R | Prot::W` composes and
    // ADL finds the operators. See DMK_FLAG_ENUM in defines.hpp for why placement and the missing semicolon matter.
    DMK_FLAG_ENUM(Prot)

} // namespace DetourModKit

#endif // DETOURMODKIT_REGION_HPP
