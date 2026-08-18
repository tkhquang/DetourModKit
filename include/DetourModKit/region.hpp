#ifndef DETOURMODKIT_REGION_HPP
#define DETOURMODKIT_REGION_HPP

/**
 * @file region.hpp
 * @brief The Region value type and the Prot protection flags, the shared range-of-memory vocabulary.
 * @details A Region pairs a base Address with a byte size, so a memory range travels as one value. Each named
 *          factory yields a Region that the caller stores, passes to a scan, and narrows with `sub()`.
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
     * @details A plain data aggregate. It maintains no invariant beyond what its fields hold, so it stays a POD-like
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
         * @details The default scope for a cascade that carries no explicit range.
         * @note Setup/control-plane only: queries the loader; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] static Region host() noexcept;

        /**
         * @brief Returns the Region spanning the module DetourModKit is linked into (the calling DLL, or the EXE when
         *        DMK is statically linked into the host process).
         * @return The owning module's mapped image span, or an empty Region if the lookup or PE-header read failed.
         * @details DetourModKit is a static library, so `own()` resolves to whichever DLL or EXE consumed it. That is
         *          distinct from @ref host(), which is always the process EXE. The lookup resolves the module that
         *          contains this function's own code, so it stays correct however the consumer packaged the library.
         * @note Setup/control-plane only: queries the loader; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] static Region own() noexcept;

        /**
         * @brief Returns the Region spanning a named, already-loaded module.
         * @param name UTF-8 module name as the loader knows it (e.g. "kernel32.dll").
         * @return The module's mapped image span, or an empty Region if @p name is empty or the module is not loaded.
         * @note Setup/control-plane only: queries the loader; call from init or a worker, not a hot callback.
         */
        [[nodiscard]] static Region module_named(std::string_view name) noexcept;

        /**
         * @brief Returns the Region spanning this process's entire user-mode address window.
         * @return The half-open span from the system minimum application address through the maximum (inclusive).
         * @details The widest scope, for a scan that cannot assume which module holds the target. It reads the
         *          system's reported application-address window, never a hardcoded ceiling.
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
        // Inside an enum with a fixed underlying type, the enumerators have that integral type (std::uint32_t), not
        // Prot, until the closing brace, so these `R | W` initializers are a plain integer OR evaluated at this point.
        // They do not depend on (and predate) the DMK_FLAG_ENUM(Prot) operators below, which only apply to Prot values.
        RW = R | W,
        RWX = R | W | X
    };

    // Emit Prot's bitwise/compound operators in this namespace (unqualified enum), so `Prot::R | Prot::W` composes and
    // ADL finds the operators. See DMK_FLAG_ENUM in defines.hpp for why placement and the missing semicolon matter.
    DMK_FLAG_ENUM(Prot)

} // namespace DetourModKit

#endif // DETOURMODKIT_REGION_HPP
