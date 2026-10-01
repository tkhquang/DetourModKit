#include "internal/xinput_route_probe.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <limits>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            constexpr std::size_t MAX_PROBE_SLOTS = 64;
            constexpr std::uintptr_t SLOT_BITS = 7;
            constexpr std::uintptr_t SLOT_MASK = (std::uintptr_t{1} << SLOT_BITS) - 1;
            constexpr std::uintptr_t CLAIMED_TOKEN = std::numeric_limits<std::uintptr_t>::max();
            constexpr std::uintptr_t MAX_NONCE = (CLAIMED_TOKEN >> SLOT_BITS) - 1;
            constexpr std::uint64_t CLOSED_BIT = std::uint64_t{1} << 63;
            constexpr std::uint64_t COUNT_MASK = CLOSED_BIT - 1;

            struct ProbeSlot
            {
                std::atomic<std::uintptr_t> token{0};
                std::atomic<std::uintptr_t> observed_token{0};
                std::atomic<std::uint64_t> owner{0};
                std::atomic<std::uint64_t> hook_epoch{0};
                std::atomic<std::uintptr_t> state_address{0};
                std::atomic<std::uint32_t> user_index{0};
                std::atomic<std::uint32_t> thread_id{0};
                std::atomic<XInputRouteMember> member{XInputRouteMember::Primary};
            };

            std::array<ProbeSlot, MAX_PROBE_SLOTS> s_probe_slots{};
            std::atomic<DWORD> s_probe_tls{TLS_OUT_OF_INDEXES};
            std::atomic<std::uint64_t> s_lease_gate{CLOSED_BIT};
            std::atomic<std::uintptr_t> s_next_nonce{1};

#if defined(DMK_ENABLE_TEST_SEAMS)
            std::atomic<bool> s_fail_reservation{false};
            std::atomic<bool> s_fail_entry{false};
            std::atomic<bool> s_fail_restore{false};
#endif

            [[nodiscard]] std::uintptr_t read_token(DWORD index) noexcept
            {
                return reinterpret_cast<std::uintptr_t>(::TlsGetValue(index));
            }

            [[nodiscard]] bool write_token(DWORD index, std::uintptr_t token, [[maybe_unused]] bool restore) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if ((restore ? s_fail_restore : s_fail_entry).load(std::memory_order_relaxed))
                {
                    return false;
                }
#endif
                return ::TlsSetValue(index, reinterpret_cast<void *>(token)) != FALSE;
            }

            [[nodiscard]] bool acquire_lease() noexcept
            {
                std::uint64_t gate = s_lease_gate.load(std::memory_order_acquire);
                while ((gate & CLOSED_BIT) == 0 && (gate & COUNT_MASK) != COUNT_MASK)
                {
                    if (s_lease_gate.compare_exchange_weak(
                            gate,
                            gate + 1,
                            std::memory_order_acq_rel,
                            std::memory_order_acquire
                        ))
                    {
                        return true;
                    }
                }
                return false;
            }

            [[nodiscard]] std::uintptr_t next_nonce() noexcept
            {
                std::uintptr_t nonce = s_next_nonce.load(std::memory_order_relaxed);
                while (nonce <= MAX_NONCE)
                {
                    if (s_next_nonce.compare_exchange_weak(
                            nonce,
                            nonce + 1,
                            std::memory_order_relaxed,
                            std::memory_order_relaxed
                        ))
                    {
                        return nonce;
                    }
                }
                return 0;
            }

            [[nodiscard]] bool valid_identity(const XInputRouteProbeIdentity &identity) noexcept
            {
                return identity.owner != 0 && identity.hook_epoch != 0 && identity.state_address != 0 &&
                       identity.user_index < 4 &&
                       (identity.member == XInputRouteMember::Primary || identity.member == XInputRouteMember::Ex);
            }
        } // namespace

        bool reserve_xinput_route_probe() noexcept
        {
            const DWORD last_error = ::GetLastError();
            DWORD index = s_probe_tls.load(std::memory_order_acquire);
            if (index == TLS_OUT_OF_INDEXES)
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (s_fail_reservation.load(std::memory_order_relaxed))
                {
                    return false;
                }
#endif
                index = ::TlsAlloc();
                if (index == TLS_OUT_OF_INDEXES)
                {
                    ::SetLastError(last_error);
                    return false;
                }
                s_probe_tls.store(index, std::memory_order_release);
            }
            // Reopen preserves leases from the revoked epoch. They still pin their index and stable slots.
            s_lease_gate.fetch_and(COUNT_MASK, std::memory_order_acq_rel);
            ::SetLastError(last_error);
            return true;
        }

        void close_xinput_route_probes() noexcept
        {
            s_lease_gate.fetch_or(CLOSED_BIT, std::memory_order_acq_rel);
        }

        std::uint64_t xinput_route_probe_inflight() noexcept
        {
            return s_lease_gate.load(std::memory_order_acquire) & COUNT_MASK;
        }

        bool release_xinput_route_probe_if_idle() noexcept
        {
            if (s_lease_gate.load(std::memory_order_acquire) != CLOSED_BIT)
            {
                return false;
            }
            const DWORD last_error = ::GetLastError();
            const DWORD index = s_probe_tls.exchange(TLS_OUT_OF_INDEXES, std::memory_order_acq_rel);
            const bool released = index == TLS_OUT_OF_INDEXES || ::TlsFree(index) != FALSE;
            if (!released)
            {
                s_probe_tls.store(index, std::memory_order_release);
            }
            ::SetLastError(last_error);
            return released;
        }

        void xinput_route_probe_record(const XInputRouteProbeIdentity &identity) noexcept
        {
            const DWORD index = s_probe_tls.load(std::memory_order_acquire);
            if (index == TLS_OUT_OF_INDEXES)
            {
                return;
            }
            const DWORD last_error = ::GetLastError();
            const std::uintptr_t token = read_token(index);
            ::SetLastError(last_error);
            const std::uintptr_t encoded_slot = token & SLOT_MASK;
            if (token == 0 || token == CLAIMED_TOKEN || encoded_slot == 0 || encoded_slot > MAX_PROBE_SLOTS)
            {
                return;
            }
            ProbeSlot &slot = s_probe_slots[encoded_slot - 1];
            if (slot.token.load(std::memory_order_acquire) != token ||
                slot.owner.load(std::memory_order_relaxed) != identity.owner ||
                slot.hook_epoch.load(std::memory_order_relaxed) != identity.hook_epoch ||
                slot.member.load(std::memory_order_relaxed) != identity.member ||
                slot.user_index.load(std::memory_order_relaxed) != identity.user_index ||
                slot.state_address.load(std::memory_order_relaxed) != identity.state_address ||
                slot.thread_id.load(std::memory_order_relaxed) != ::GetCurrentThreadId() ||
                slot.token.load(std::memory_order_acquire) != token)
            {
                return;
            }
            // A delayed stale write carries its own nonce and cannot authenticate a reused slot.
            slot.observed_token.store(token, std::memory_order_release);
        }

        XInputRouteProbe::XInputRouteProbe(const XInputRouteProbeIdentity &identity) noexcept
        {
            if (!valid_identity(identity) || !acquire_lease())
            {
                return;
            }
            const DWORD last_error = ::GetLastError();
            m_index = s_probe_tls.load(std::memory_order_acquire);
            if (m_index != TLS_OUT_OF_INDEXES)
            {
                const std::uintptr_t nonce = next_nonce();
                if (nonce != 0)
                {
                    for (std::size_t i = 0; i < s_probe_slots.size(); ++i)
                    {
                        ProbeSlot &slot = s_probe_slots[i];
                        std::uintptr_t expected = 0;
                        if (!slot.token.compare_exchange_strong(
                                expected,
                                CLAIMED_TOKEN,
                                std::memory_order_acquire,
                                std::memory_order_relaxed
                            ))
                        {
                            continue;
                        }
                        m_slot = static_cast<std::uint32_t>(i);
                        m_token = (nonce << SLOT_BITS) | (i + 1);
                        slot.observed_token.store(0, std::memory_order_relaxed);
                        slot.owner.store(identity.owner, std::memory_order_relaxed);
                        slot.hook_epoch.store(identity.hook_epoch, std::memory_order_relaxed);
                        slot.member.store(identity.member, std::memory_order_relaxed);
                        slot.user_index.store(identity.user_index, std::memory_order_relaxed);
                        slot.state_address.store(identity.state_address, std::memory_order_relaxed);
                        slot.thread_id.store(::GetCurrentThreadId(), std::memory_order_relaxed);
                        slot.token.store(m_token, std::memory_order_release);
                        m_previous_token = read_token(m_index);
                        m_admitted = write_token(m_index, m_token, false);
                        if (!m_admitted)
                        {
                            slot.token.store(0, std::memory_order_release);
                            m_token = 0;
                        }
                        break;
                    }
                }
            }
            ::SetLastError(last_error);
            if (!m_admitted)
            {
                s_lease_gate.fetch_sub(1, std::memory_order_release);
            }
        }

        XInputRouteProbe::~XInputRouteProbe() noexcept
        {
            if (!m_admitted)
            {
                return;
            }
            (void)finish();
            s_probe_slots[m_slot].token.store(0, std::memory_order_release);
            s_lease_gate.fetch_sub(1, std::memory_order_release);
        }

        bool XInputRouteProbe::finish() noexcept
        {
            if (m_finished)
            {
                return m_receipt;
            }
            m_finished = true;
            if (!m_admitted)
            {
                return false;
            }
            const DWORD last_error = ::GetLastError();
            const bool current = read_token(m_index) == m_token;
            const bool restored = write_token(m_index, m_previous_token, true);
            ::SetLastError(last_error);
            m_receipt =
                current && restored && s_probe_slots[m_slot].observed_token.load(std::memory_order_acquire) == m_token;
            return m_receipt;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        void set_xinput_route_probe_failures_for_test(bool reservation, bool entry, bool restore) noexcept
        {
            s_fail_reservation.store(reservation, std::memory_order_relaxed);
            s_fail_entry.store(entry, std::memory_order_relaxed);
            s_fail_restore.store(restore, std::memory_order_relaxed);
        }

        std::uint32_t xinput_route_probe_tls_index_for_test() noexcept
        {
            return s_probe_tls.load(std::memory_order_acquire);
        }

        std::uintptr_t xinput_route_probe_token_for_test() noexcept
        {
            const DWORD last_error = ::GetLastError();
            const DWORD index = s_probe_tls.load(std::memory_order_acquire);
            const std::uintptr_t token = index == TLS_OUT_OF_INDEXES ? 0 : read_token(index);
            ::SetLastError(last_error);
            return token;
        }

        bool set_xinput_route_probe_token_for_test(std::uintptr_t token) noexcept
        {
            const DWORD last_error = ::GetLastError();
            const DWORD index = s_probe_tls.load(std::memory_order_acquire);
            const bool stored =
                index != TLS_OUT_OF_INDEXES && ::TlsSetValue(index, reinterpret_cast<void *>(token)) != FALSE;
            ::SetLastError(last_error);
            return stored;
        }
#endif
    } // namespace detail
} // namespace DetourModKit
