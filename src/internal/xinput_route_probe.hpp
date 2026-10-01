#ifndef DETOURMODKIT_INTERNAL_XINPUT_ROUTE_PROBE_HPP
#define DETOURMODKIT_INTERNAL_XINPUT_ROUTE_PROBE_HPP

#include <cstdint>

namespace DetourModKit::detail
{
    /** @brief The required export whose scoped call supplies a receipt. */
    enum class XInputRouteMember : std::uint8_t
    {
        Primary,
        Ex
    };

    /** @brief Exact identity of one export invocation under an interception snapshot. */
    struct XInputRouteProbeIdentity
    {
        std::uint64_t owner{0};
        std::uint64_t hook_epoch{0};
        XInputRouteMember member{XInputRouteMember::Primary};
        std::uint32_t user_index{0};
        std::uintptr_t state_address{0};
    };

    /**
     * @brief Reserves receipt TLS and opens probe admission. Call under the interception control lock.
     * @return false when TLS reservation fails. Existing leases retain their index across a reopen.
     */
    [[nodiscard]] bool reserve_xinput_route_probe() noexcept;

    /** @brief Closes probe admission for XInput teardown. */
    void close_xinput_route_probes() noexcept;

    /** @brief Returns the number of leases across upstream calls and final snapshot publication. */
    [[nodiscard]] std::uint64_t xinput_route_probe_inflight() noexcept;

    /**
     * @brief Returns receipt TLS after closed admission and zero probe leases.
     * @details Call under the interception control lock after every callback that reads receipt TLS drains.
     * @return false while admission is open or any lease remains. A refused release retains the index.
     */
    [[nodiscard]] bool release_xinput_route_probe_if_idle() noexcept;

    /**
     * @brief Records this thread's exact scoped export invocation without an application lock or C++ allocation.
     * @details A receipt proves this invocation only. The identity must match its private token and native thread.
     */
    void xinput_route_probe_record(const XInputRouteProbeIdentity &identity) noexcept;

    /**
     * @brief Owns permanent receipt storage and a counted upstream-call lease.
     * @details Construct before the export call and retain through final snapshot publication. Nested probes restore
     *          prior numeric TLS tokens in reverse order. Keep the object on its construction thread.
     */
    class XInputRouteProbe
    {
    public:
        /** @brief Opens one probe. Refuse the export call when admitted() is false. */
        explicit XInputRouteProbe(const XInputRouteProbeIdentity &identity) noexcept;
        /** @brief Restores an unfinished token, clears its receipt slot, and releases the complete-call lease. */
        ~XInputRouteProbe() noexcept;

        XInputRouteProbe(const XInputRouteProbe &) = delete;
        XInputRouteProbe &operator=(const XInputRouteProbe &) = delete;
        XInputRouteProbe(XInputRouteProbe &&) = delete;
        XInputRouteProbe &operator=(XInputRouteProbe &&) = delete;

        /** @brief Reports whether the lease and its TLS token were acquired. */
        [[nodiscard]] bool admitted() const noexcept { return m_admitted; }

        /**
         * @brief Restores prior TLS and returns whether this exact invocation supplied a receipt.
         * @details The lease stays counted until destruction. A repeated call returns the cached verdict.
         * @return false after an entry failure, unmatched receipt, token mismatch, or failed TLS restore.
         */
        [[nodiscard]] bool finish() noexcept;

    private:
        std::uintptr_t m_token{0};
        std::uintptr_t m_previous_token{0};
        std::uint32_t m_index{0};
        std::uint32_t m_slot{0};
        bool m_admitted{false};
        bool m_finished{false};
        bool m_receipt{false};
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    /** @brief Forces TLS reservation, probe entry, or token restore failures for deterministic proofs. */
    void set_xinput_route_probe_failures_for_test(bool reservation, bool entry, bool restore) noexcept;
    /** @brief Returns the private receipt TLS index, or TLS_OUT_OF_INDEXES. */
    [[nodiscard]] std::uint32_t xinput_route_probe_tls_index_for_test() noexcept;
    /** @brief Returns this thread's numeric receipt token, or zero without an index. */
    [[nodiscard]] std::uintptr_t xinput_route_probe_token_for_test() noexcept;
    /** @brief Replaces this thread's token to verify nonce and unrelated-call refusal. */
    [[nodiscard]] bool set_xinput_route_probe_token_for_test(std::uintptr_t token) noexcept;
#endif
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_XINPUT_ROUTE_PROBE_HPP
