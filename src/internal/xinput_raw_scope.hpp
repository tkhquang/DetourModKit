#ifndef DETOURMODKIT_INTERNAL_XINPUT_RAW_SCOPE_HPP
#define DETOURMODKIT_INTERNAL_XINPUT_RAW_SCOPE_HPP

#include <windows.h>

#include <cstdint>

namespace DetourModKit::detail
{
    /**
     * @brief Reserves shared XInput scope TLS for one local owner.
     * @param error Receives the platform error after failure, when supplied.
     * @return False when the descriptor or TLS index is unavailable.
     * @note Setup/control-plane only. Each successful call requires one release after callbacks and samples drain.
     * @note Lock order: local owner SRW lock, then process descriptor mutex.
     */
    [[nodiscard]] bool acquire_xinput_raw_scope_owner(DWORD *error = nullptr) noexcept;

    /**
     * @brief Releases one owner after callbacks and samples drain.
     * @note Setup/control-plane only. Retained routes must retain their owner.
     */
    void release_xinput_raw_scope_owner() noexcept;

    /** @brief Returns the number of local raw and consume scopes that remain active. */
    [[nodiscard]] std::uint64_t active_xinput_raw_scopes() noexcept;

    /**
     * @brief Returns whether the live shared consume context remains healthy.
     * @note Callback-safe. A context fault disables every compatible copy until all owners retire.
     */
    [[nodiscard]] bool xinput_consume_context_healthy() noexcept;

    /**
     * @brief Returns whether this thread has a raw scope from a compatible copy.
     * @note Callback-safe. The query preserves the caller's last-error value and takes no application lock.
     */
    [[nodiscard]] bool is_xinput_raw_call() noexcept;

    /**
     * @brief Marks a nested raw sample without a C++ allocation or application lock.
     * @note Refuse the sample after failed admission. Disarm its consume cycle after a failed finish.
     */
    class XInputRawScope
    {
    public:
        /** @brief Attempts raw-sample admission and preserves the caller's last-error value. */
        XInputRawScope() noexcept;
        /** @brief Restores the previous depth if finish did not already restore it. */
        ~XInputRawScope() noexcept;

        XInputRawScope(const XInputRawScope &) = delete;
        XInputRawScope &operator=(const XInputRawScope &) = delete;
        XInputRawScope(XInputRawScope &&) = delete;
        XInputRawScope &operator=(XInputRawScope &&) = delete;

        /** @brief Returns whether the entry store succeeded. */
        [[nodiscard]] bool admitted() const noexcept { return m_admitted; }

        /**
         * @brief Restores the previous depth and preserves the provider's last-error value.
         * @return False after a restore failure. Repeated calls retain the first result.
         */
        [[nodiscard]] bool finish() noexcept;

    private:
        DWORD m_index{TLS_OUT_OF_INDEXES};
        std::uintptr_t m_previous_depth{0};
        bool m_admitted{false};
        bool m_active{false};
        bool m_restored{true};
    };

    /**
     * @brief Shares original digital buttons across compatible detours for one state call.
     * @note Callback-safe. Finish before a local mask. The state address serves only as a numeric identity.
     */
    class XInputConsumeScope
    {
    public:
        /** @brief Attempts admission for users 0 through 3 and the numeric state identity. */
        XInputConsumeScope(DWORD user, const void *state_address) noexcept;
        /** @brief Restores the prior context if finish did not already restore it. */
        ~XInputConsumeScope() noexcept;

        XInputConsumeScope(const XInputConsumeScope &) = delete;
        XInputConsumeScope &operator=(const XInputConsumeScope &) = delete;
        XInputConsumeScope(XInputConsumeScope &&) = delete;
        XInputConsumeScope &operator=(XInputConsumeScope &&) = delete;

        /** @brief Returns whether the entry stores succeeded. */
        [[nodiscard]] bool admitted() const noexcept { return m_admitted; }

        /**
         * @brief Returns shared original buttons or reseeds them after a visible upstream button change.
         * @return False after a context fault. The output remains unchanged after failure.
         */
        [[nodiscard]] bool original_buttons(WORD observed, WORD &original) noexcept;

        /**
         * @brief Restores the prior context and preserves the provider's last-error value.
         * @return False after a context fault. Repeated calls retain the first result.
         * @note The expected buttons from the lower compatible detour remain unchanged.
         */
        [[nodiscard]] bool finish() noexcept;

        /**
         * @brief Publishes the proposed return buttons before the prior context resumes.
         * @return False after a context fault. Commit the proposed buttons only after success.
         */
        [[nodiscard]] bool finish(WORD returned_buttons) noexcept;

    private:
        [[nodiscard]] bool finish_context(bool publish_return, WORD returned_buttons) noexcept;

        DWORD m_identity_index{TLS_OUT_OF_INDEXES};
        DWORD m_metadata_index{TLS_OUT_OF_INDEXES};
        DWORD m_user{0};
        std::uintptr_t m_identity{0};
        std::uintptr_t m_previous_identity{0};
        std::uintptr_t m_previous_metadata{0};
        std::uint32_t m_depth{0};
        bool m_joined{false};
        bool m_admitted{false};
        bool m_active{false};
        bool m_restored{true};
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    /** @brief Selects one deterministic platform refusal on the calling thread. */
    enum class XInputRawScopeFailure : std::uint8_t
    {
        None,
        Reservation,
        EntryStore,
        Restore,
        DescriptorInit,
        DescriptorVersion,
        IdentityReservation,
        MetadataReservation,
        ConsumeEntryIdentity,
        ConsumeEntryMetadata,
        ConsumeEntryRollback,
        ConsumeOriginalStore,
        ConsumeRestoreIdentity,
        ConsumeRestoreMetadata,
    };

    /** @brief Sets one refusal for the calling thread. None clears that thread's refusal. */
    [[nodiscard]] bool set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure failure) noexcept;
    /** @brief Returns the cached TLS index or TLS_OUT_OF_INDEXES. */
    [[nodiscard]] DWORD xinput_raw_scope_index_for_test() noexcept;
    /** @brief Returns the owner count in the shared descriptor. */
    [[nodiscard]] std::uint32_t xinput_raw_scope_owners_for_test() noexcept;
    /** @brief Returns this thread's raw depth without a last-error change. */
    [[nodiscard]] std::uintptr_t xinput_raw_scope_depth_for_test() noexcept;
    /** @brief Returns the shared descriptor address. */
    [[nodiscard]] std::uintptr_t xinput_raw_scope_descriptor_for_test() noexcept;
    /** @brief Returns the cached consume identity index or TLS_OUT_OF_INDEXES. */
    [[nodiscard]] DWORD xinput_consume_identity_index_for_test() noexcept;
    /** @brief Returns the cached consume metadata index or TLS_OUT_OF_INDEXES. */
    [[nodiscard]] DWORD xinput_consume_metadata_index_for_test() noexcept;
#endif
} // namespace DetourModKit::detail

#endif // DETOURMODKIT_INTERNAL_XINPUT_RAW_SCOPE_HPP
