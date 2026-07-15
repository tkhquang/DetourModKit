/**
 * @file memory_guarded.cpp
 * @brief The single SEH-confined engine TU: every guarded foreign read/write and the protection-changing patch path.
 *
 * All Structured Exception Handling lives here. On MSVC the guarded copies and the chain walk run inside frame-based
 * __try / __except whose filter is the shared detail::is_guarded_read_fault set. MinGW/GCC has no __try, so this file
 * also owns a process-wide vectored exception handler that turns a fault inside an explicitly-armed foreign range into
 * a clean failure via __builtin_longjmp; the public memory surface and the scan engine reach that machinery only
 * through the small seam declared in memory_guarded.hpp and memory_fault.hpp. Confining SEH/VEH to this one translation
 * unit is what keeps the installed memory.hpp free of <windows.h> and structured-exception constructs.
 */

#include "internal/memory_guarded.hpp"
#include "internal/memory_fault.hpp"

#include "DetourModKit/memory.hpp"

#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h> // __movsb -- forward, ASan-safe foreign-memory copy
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <thread>
#include <unordered_map>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        // Page-protection flag groups the VirtualQuery-validated fallbacks need to classify a region. The cache TU
        // keeps its own copy of these masks; the small duplication keeps this engine TU independent of the cache
        // subsystem.
        constexpr DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD WRITE_PERMISSION_FLAGS =
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD NOACCESS_GUARD_FLAGS = PAGE_NOACCESS | PAGE_GUARD;

        // STATUS_GUARD_PAGE_VIOLATION, spelled as a literal (matching <winnt.h>) so it needs no ntstatus.h include and
        // cannot collide with a platform macro of the same name.
        constexpr unsigned long GUARD_PAGE_FAULT_CODE = 0x80000001ul;

        // Re-arm a PAGE_GUARD page the OS consumed while dispatching a guarded read's fault. Touching a guard page
        // raises STATUS_GUARD_PAGE_VIOLATION and the OS clears that page's PAGE_GUARD bit before dispatching the fault,
        // so a guarded read that faults on a foreign guard page (for example another thread's stack guard) would leave
        // the host's fence permanently disarmed and let an immediate second read succeed straight through it -- fail
        // open on memory the host deliberately fenced. On a claimed guard-page fault this re-applies PAGE_GUARD over
        // the faulting page's current protection so the fence is restored before the read is reported as failed; the
        // read still fails closed, and the host's next access re-faults exactly as intended. Any non-guard fault, or a
        // record that carries no faulting address, is left untouched. Callable from both the MinGW vectored handler and
        // an MSVC __except filter: VirtualQuery / VirtualProtect neither allocate nor take a lock the
        // exception-dispatch context forbids (unlike the __emutls thread-local path the handler must avoid).
        void rearm_guard_page_if_consumed(const EXCEPTION_RECORD *record) noexcept
        {
            if (record->ExceptionCode != GUARD_PAGE_FAULT_CODE || record->NumberParameters < 2)
            {
                return;
            }
            const auto fault_address = reinterpret_cast<LPVOID>(record->ExceptionInformation[1]);
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(fault_address, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT)
            {
                return;
            }
            // The OS already cleared PAGE_GUARD, so mbi.Protect reads back without it; OR it back on to restore the
            // fence over the (page containing the) faulting address.
            DWORD previous = 0;
            VirtualProtect(fault_address, 1, mbi.Protect | PAGE_GUARD, &previous);
        }
    } // namespace

    namespace
    {
        // Page protections that carry execute. A writable protection derived for a patch must preserve execute for a
        // code region and must NOT add it to a data region.
        constexpr DWORD EXECUTE_PERMISSION_FLAGS =
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        // Derive a writable protection from a region's current protection: an executable region becomes
        // PAGE_EXECUTE_READWRITE (keeps execute so DEP does not fault its next execution), any other becomes
        // PAGE_READWRITE. A data page therefore never gains execute, and an already-writable region maps to the same
        // writable family it already had.
        [[nodiscard]] DWORD writable_protection_for(DWORD current) noexcept
        {
            return (current & EXECUTE_PERMISSION_FLAGS) != 0 ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        }

        [[nodiscard]] std::uintptr_t system_page_size() noexcept
        {
            static const std::uintptr_t size = []() noexcept
            {
                SYSTEM_INFO info{};
                GetSystemInfo(&info);
                return static_cast<std::uintptr_t>(info.dwPageSize);
            }();
            return size;
        }

        [[nodiscard]] std::uintptr_t page_floor(std::uintptr_t address) noexcept
        {
            return address & ~(system_page_size() - 1);
        }

        [[nodiscard]] std::uintptr_t page_ceiling(std::uintptr_t address) noexcept
        {
            const std::uintptr_t mask = system_page_size() - 1;
            return (address + mask) & ~mask;
        }

        // Use an explicit forward copy so a fault at the first target byte proves that no later target byte was
        // written. The intrinsic/inline instruction also bypasses ASan's memcpy interceptor for deliberate
        // foreign-memory access.
        inline void copy_with_fault_progress(void *destination, const void *source, std::size_t bytes) noexcept
        {
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
            __movsb(static_cast<unsigned char *>(destination), static_cast<const unsigned char *>(source), bytes);
#else
            // Fixed-width copies compile to one destination store on both supported x64 toolchains. They preserve the
            // first-byte classification while avoiding REP setup on the overwhelmingly common scalar-write sizes.
            switch (bytes)
            {
            case 1:
                std::memcpy(destination, source, 1);
                return;
            case 2:
                std::memcpy(destination, source, 2);
                return;
            case 4:
                std::memcpy(destination, source, 4);
                return;
            case 8:
                std::memcpy(destination, source, 8);
                return;
            default:
                break;
            }
#if defined(_MSC_VER)
            __movsb(static_cast<unsigned char *>(destination), static_cast<const unsigned char *>(source), bytes);
#elif defined(__x86_64__)
            void *current_destination = destination;
            const void *current_source = source;
            std::size_t remaining = bytes;
            __asm__ __volatile__("rep movsb"
                                 : "+D"(current_destination), "+S"(current_source), "+c"(remaining)
                                 :
                                 : "memory");
#else
            std::memcpy(destination, source, bytes);
#endif
#endif
        }

        // Adds a signed byte offset to an address, rejecting an addition that wraps the address space. A positive
        // offset must not carry the result below the base; a negative offset's magnitude must not exceed the base. This
        // is what stops a pointer-chain hop near the top or bottom of the address space from producing a wrapped link
        // or leaf that a modulo-2^64 addition would report as a plausible success.
        [[nodiscard]] bool checked_offset(std::uintptr_t base, std::ptrdiff_t offset, std::uintptr_t &out) noexcept
        {
            if (offset >= 0)
            {
                const std::uintptr_t delta = static_cast<std::uintptr_t>(offset);
                if (base > UINTPTR_MAX - delta)
                {
                    return false;
                }
                out = base + delta;
                return true;
            }
            // offset < 0: negating in uintptr_t is well-defined; reject when the magnitude would underflow past zero.
            const std::uintptr_t magnitude = static_cast<std::uintptr_t>(-(offset + 1)) + 1U;
            if (magnitude > base)
            {
                return false;
            }
            out = base - magnitude;
            return true;
        }

        struct PageProtectionHolder
        {
            std::uint64_t transaction_id = 0;
            DWORD target_protection = 0;
        };

        // The first holder is inline because non-overlapping guards are the common case. Additional holders preserve
        // acquisition order so removing an inner transaction can restore the newest surviving target.
        struct PageProtectionState
        {
            DWORD original_protection = 0;
            PageProtectionHolder first_holder{};
            std::vector<PageProtectionHolder> newer_holders;

            [[nodiscard]] bool empty() const noexcept { return first_holder.transaction_id == 0; }

            void add_holder(PageProtectionHolder holder)
            {
                if (empty())
                {
                    first_holder = holder;
                    return;
                }
                newer_holders.push_back(holder);
            }

            [[nodiscard]] bool remove_holder(std::uint64_t transaction_id, DWORD *removed_target,
                                             DWORD *desired_protection) noexcept
            {
                DWORD target = 0;
                if (first_holder.transaction_id == transaction_id)
                {
                    target = first_holder.target_protection;
                    if (newer_holders.empty())
                    {
                        first_holder = {};
                    }
                    else
                    {
                        first_holder = newer_holders.front();
                        newer_holders.erase(newer_holders.begin());
                    }
                }
                else
                {
                    const auto holder = std::find_if(newer_holders.begin(), newer_holders.end(),
                                                     [transaction_id](const PageProtectionHolder &candidate) noexcept
                                                     { return candidate.transaction_id == transaction_id; });
                    if (holder == newer_holders.end())
                    {
                        return false;
                    }
                    target = holder->target_protection;
                    newer_holders.erase(holder);
                }

                if (removed_target != nullptr)
                {
                    *removed_target = target;
                }
                if (desired_protection != nullptr)
                {
                    *desired_protection = empty() ? original_protection
                                                  : (newer_holders.empty() ? first_holder.target_protection
                                                                           : newer_holders.back().target_protection);
                }
                return true;
            }
        };

        SRWLOCK s_protection_ledger_lock = SRWLOCK_INIT;
        std::uint64_t s_next_transaction_id = 1;

        class ProtectionLedgerLock
        {
        public:
            ProtectionLedgerLock() noexcept { AcquireSRWLockExclusive(&s_protection_ledger_lock); }

            ~ProtectionLedgerLock() noexcept { ReleaseSRWLockExclusive(&s_protection_ledger_lock); }

            ProtectionLedgerLock(const ProtectionLedgerLock &) = delete;
            ProtectionLedgerLock &operator=(const ProtectionLedgerLock &) = delete;
            ProtectionLedgerLock(ProtectionLedgerLock &&) = delete;
            ProtectionLedgerLock &operator=(ProtectionLedgerLock &&) = delete;
        };

        // The ledger intentionally has process lifetime so late teardown cannot observe a destroyed registry.
        [[nodiscard]] std::unordered_map<std::uintptr_t, PageProtectionState> *protection_ledger() noexcept
        {
            static std::unordered_map<std::uintptr_t, PageProtectionState> *const ledger =
                new (std::nothrow) std::unordered_map<std::uintptr_t, PageProtectionState>();
            return ledger;
        }

        [[nodiscard]] std::uint64_t next_transaction_id() noexcept
        {
            const std::uint64_t id = s_next_transaction_id++;
            if (s_next_transaction_id == 0)
            {
                s_next_transaction_id = 1;
            }
            return id;
        }

        void ledger_cancel_pages(std::uintptr_t page_lo, std::uintptr_t page_hi, std::uint64_t transaction_id) noexcept
        {
            auto *const ledger = protection_ledger();
            if (ledger == nullptr)
            {
                return;
            }
            const std::uintptr_t step = system_page_size();
            for (std::uintptr_t page = page_lo; page < page_hi; page += step)
            {
                const auto entry = ledger->find(page);
                if (entry == ledger->end())
                {
                    continue;
                }
                if (entry->second.remove_holder(transaction_id, nullptr, nullptr) && entry->second.empty())
                {
                    ledger->erase(entry);
                }
            }
        }

        [[nodiscard]] bool ledger_acquire_pages(std::uintptr_t page_lo, std::uintptr_t page_hi,
                                                std::uint64_t transaction_id, DWORD target_protection,
                                                DWORD current_original) noexcept
        {
            auto *const ledger = protection_ledger();
            if (ledger == nullptr)
            {
                return false;
            }
            const std::uintptr_t step = system_page_size();
            std::uintptr_t page = page_lo;
            try
            {
                for (; page < page_hi; page += step)
                {
                    auto entry = ledger->find(page);
                    if (entry == ledger->end())
                    {
                        PageProtectionState state{};
                        state.original_protection = current_original;
                        state.first_holder = PageProtectionHolder{transaction_id, target_protection};
                        entry = ledger->try_emplace(page, std::move(state)).first;
                    }
                    else
                    {
                        entry->second.add_holder(PageProtectionHolder{transaction_id, target_protection});
                    }
                }
            }
            catch (...)
            {
                ledger_cancel_pages(page_lo, page, transaction_id);
                return false;
            }
            return true;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        // Thread-local seams keep one test's injection from perturbing another thread's guarded operation.
        thread_local bool s_seam_flush_fails = false;
        thread_local bool s_seam_forward_copy = false;
        thread_local std::size_t s_seam_last_prefix = 0;
        thread_local std::uint64_t s_seam_virtual_protect_failures = 0;
        thread_local std::size_t s_seam_virtual_protect_call = 0;
#endif

        [[nodiscard]] bool change_page_protection(LPVOID address, SIZE_T bytes, DWORD protection,
                                                  DWORD *previous) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            const std::size_t call = s_seam_virtual_protect_call++;
            if (call < 64 && (s_seam_virtual_protect_failures & (std::uint64_t{1} << call)) != 0)
            {
                SetLastError(ERROR_ACCESS_DENIED);
                return false;
            }
#endif
            return VirtualProtect(address, bytes, protection, previous) != 0;
        }
    } // namespace

#ifdef _MSC_VER
    // The shared frame-based SEH filter declared in memory_fault.hpp. Every MSVC guarded foreign read -- the memory
    // engine's read / write / chain-walk paths below and the scanner's region / window sweeps -- routes its __except
    // through here, so the claimed fault set AND the guard-page re-arm are identical across them. Re-arming a
    // PAGE_GUARD the OS cleared on dispatch, before the read fails closed, is what stops a swallowed foreign guard-page
    // fault from leaving the host's fence disarmed. GetExceptionInformation() is valid only inside a filter expression,
    // so the call sites pass its EXCEPTION_POINTERS in rather than the bare code, which also makes the faulting address
    // reachable for the re-arm.
    long detail::guarded_fault_filter(EXCEPTION_POINTERS *info) noexcept
    {
        const EXCEPTION_RECORD *const record = info->ExceptionRecord;
        if (!detail::is_guarded_read_fault(record->ExceptionCode))
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        rearm_guard_page_if_consumed(record);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    long detail::guarded_range_fault_filter(EXCEPTION_POINTERS *info, std::uintptr_t lo, std::uintptr_t hi,
                                            volatile std::uintptr_t *fault_address_out) noexcept
    {
        const EXCEPTION_RECORD *const record = info->ExceptionRecord;
        if (!detail::is_guarded_read_fault(record->ExceptionCode))
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // A guarded foreign access can only fault with a hardware access-violation, guard-page, or in-page error, all
        // of which carry the faulting data address in ExceptionInformation[1]. A record without it (a host
        // RaiseException reusing one of these NTSTATUS codes) is not this operation's fault and is passed through.
        if (record->NumberParameters < 2)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // Claim the fault only when it lands inside the declared foreign span. A fault OUTSIDE [lo, hi) -- an unrelated
        // DMK defect that happens to occur inside the __try, or a fault on the caller-owned source/destination buffer
        // rather than the foreign target -- reaches the host's own handlers instead of being silently swallowed. This
        // matches the MinGW vectored handler, which arms only [lo, hi).
        const std::uintptr_t fault_address = static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
        if (fault_address < lo || fault_address >= hi)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (fault_address_out != nullptr)
        {
            *fault_address_out = fault_address;
        }
        rearm_guard_page_if_consumed(record);
        return EXCEPTION_EXECUTE_HANDLER;
    }
#endif

#ifndef _MSC_VER
    // MinGW/GCC has no __try / __except, so the foreign-memory probes in this file cannot wrap their accesses in
    // frame-based SEH the way the MSVC paths do. A single process-wide vectored exception handler provides the
    // equivalent fault guard: each guarded access marks the foreign range it is about to touch in a thread-local slot,
    // and a fault inside that range is intercepted and turned into a clean failure instead of terminating the host. The
    // guarded path avoids a per-call VirtualQuery on successful terminal reads/writes and keeps stale state from
    // authorizing unguarded dereferences after a page is reprotected.
    namespace
    {
        // VirtualQuery-validated read. It is the fallback used only when the vectored handler could not be installed.
        // The copy itself goes through ReadProcessMemory so a page that changes after the query fails as an API result
        // rather than as a user-mode fault.
        bool virtualquery_validated_copy(std::uintptr_t addr, void *out, std::size_t bytes) noexcept
        {
            std::size_t copied = 0;
            while (copied < bytes)
            {
                const std::uintptr_t cur = addr + copied;
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void *>(cur), &mbi, sizeof(mbi)))
                    return false;
                if (mbi.State != MEM_COMMIT)
                    return false;
                if ((mbi.Protect & READ_PERMISSION_FLAGS) == 0 || (mbi.Protect & NOACCESS_GUARD_FLAGS) != 0)
                    return false;

                const std::uintptr_t region_start = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t region_end = region_start + mbi.RegionSize;
                if (region_end < region_start)
                    return false;
                if (cur < region_start || cur >= region_end)
                    return false;

                const std::size_t available = static_cast<std::size_t>(region_end - cur);
                const std::size_t remaining = bytes - copied;
                const std::size_t to_copy = (remaining < available) ? remaining : available;
                SIZE_T copied_now = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void *>(cur),
                                       static_cast<std::byte *>(out) + copied, to_copy, &copied_now) ||
                    copied_now != to_copy)
                    return false;
                copied += to_copy;
            }
            return true;
        }

        // VirtualQuery-validated write fallback for MinGW when no frame/vectored fault guard is available. It never
        // changes page protection: if the current protection is not writable, the write fails closed. The copy itself
        // goes through WriteProcessMemory so a page that changes after the query fails as an API result rather than as
        // a user-mode fault.
        detail::GuardedWriteStatus virtualquery_validated_write(std::uintptr_t addr, const void *source,
                                                                std::size_t bytes) noexcept
        {
            std::size_t copied = 0;
            while (copied < bytes)
            {
                const std::uintptr_t cur = addr + copied;
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQuery(reinterpret_cast<const void *>(cur), &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
                    (mbi.Protect & WRITE_PERMISSION_FLAGS) == 0 || (mbi.Protect & NOACCESS_GUARD_FLAGS) != 0)
                    return copied == 0 ? detail::GuardedWriteStatus::NotWritten
                                       : detail::GuardedWriteStatus::MayBePartial;

                const std::uintptr_t region_start = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::uintptr_t region_end = region_start + mbi.RegionSize;
                if (region_end < region_start || cur < region_start || cur >= region_end)
                    return copied == 0 ? detail::GuardedWriteStatus::NotWritten
                                       : detail::GuardedWriteStatus::MayBePartial;

                const std::size_t available = static_cast<std::size_t>(region_end - cur);
                const std::size_t remaining = bytes - copied;
                const std::size_t to_copy = (remaining < available) ? remaining : available;
                SIZE_T copied_now = 0;
                const bool ok =
                    WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(cur),
                                       static_cast<const std::byte *>(source) + copied, to_copy, &copied_now) != 0;
                copied += copied_now;
                if (!ok || copied_now != to_copy)
                    return copied == 0 ? detail::GuardedWriteStatus::NotWritten
                                       : detail::GuardedWriteStatus::MayBePartial;
            }
            return detail::GuardedWriteStatus::Ok;
        }

#if defined(_WIN64)
        // Per-access record describing the foreign range and the recovery snapshot. It lives on the guarded access's
        // own stack (one per nested-free synchronous access) and is published to the thread's Win32 TLS slot for the
        // duration of the access; the handler reads that slot. A Win32 TLS slot is used rather than a thread_local /
        // __thread because mingw lowers thread-locals to __emutls_get_address, which allocates and locks on a thread's
        // first access -- forbidden in the exception-dispatch context the handler runs in. TlsGetValue is documented to
        // be callable there: it reads the thread's TLS array with no allocation and no lock, and returns null on any
        // thread that has not armed an access.
        struct VehAccessGuard
        {
            void *env[5]; // __builtin_setjmp buffer; the recovery stub longjmps through it (5 words, GCC ABI)
            std::uintptr_t guard_lo; // first byte of the foreign range being accessed
            std::uintptr_t guard_hi; // one past the last byte of that range
            volatile std::uintptr_t fault_address;
        };

        std::mutex s_veh_mutex;
        std::atomic<void *> s_veh_handle{nullptr};
        // Process-lifetime TLS index, allocated once and reused across install/remove cycles (never freed so a removal
        // can never invalidate an index a concurrent access still holds). The handler reads it with an acquire load.
        std::atomic<DWORD> s_veh_tls_index{TLS_OUT_OF_INDEXES};

        // Count of accesses currently on the guarded path, striped across cache-line-padded per-thread counters rather
        // than one global atomic. Every guarded read/write bumps this counter twice (enter + leave), so on a busy
        // multi-threaded workload a single global counter line would ping-pong across cores; striping lands each
        // thread's increment on its own line. release_guarded_engine drains the SUM to zero before unregistering the
        // handler, and the Dekker publish/drain protocol is preserved exactly: the handle-null store, the access-side
        // stripe increment, and the drain's stripe loads are seq_cst, so an access that observed a live handle is
        // counted before the drain can observe zero (see remove_veh_handler / veh_read_bytes).
        constexpr std::size_t VEH_IN_FLIGHT_STRIPE_COUNT = 64;

        // alignas(64) needs no MSVC C4324 warning suppression here: this whole region is compiled only under
        // #ifndef _MSC_VER, so an MSVC build never sees the padded struct.
        struct alignas(64) VehInFlightStripe
        {
            std::atomic<int> count{0};
        };

        std::array<VehInFlightStripe, VEH_IN_FLIGHT_STRIPE_COUNT> s_veh_in_flight_stripes{};

        // This thread's in-flight stripe, derived from its Win32 thread id by golden-ratio bit-mixing. A guarded access
        // is synchronous and nested-free on one thread, and a thread id is stable for the thread's life, so the same
        // stripe carries both the enter increment and the leave decrement and a stripe never goes negative. A
        // thread_local round-robin counter would be simpler, but its first touch lowers to __emutls_get_address on
        // MinGW, which allocates and locks -- the exact hazard this file uses Win32 TLS (not thread_local) to keep off
        // the guarded access path, which can run under loader lock when a hook is installed or a scan is driven from
        // DllMain. GetCurrentThreadId is allocation-free and lock-free, so it is safe there; two thread ids colliding
        // onto one stripe only adds minor contention on that line, never a miscount.
        [[nodiscard]] inline std::size_t veh_in_flight_stripe_index() noexcept
        {
            const std::uint64_t mixed = static_cast<std::uint64_t>(GetCurrentThreadId()) * 0x9E3779B97F4A7C15ULL;
            return static_cast<std::size_t>(mixed >> 48) % VEH_IN_FLIGHT_STRIPE_COUNT;
        }

        // Sum of every in-flight stripe: the number of guarded accesses currently on the handler path.
        // remove_veh_handler spins on this reaching zero (under seq_cst) after publishing s_veh_handle = nullptr.
        [[nodiscard]] inline int veh_in_flight_total() noexcept
        {
            int total = 0;
            for (const VehInFlightStripe &stripe : s_veh_in_flight_stripes)
            {
                total += stripe.count.load(std::memory_order_seq_cst);
            }
            return total;
        }

        // Recovery stub the handler redirects a faulting thread into. __builtin_longjmp restores the stack pointer,
        // frame pointer and program counter from the snapshot the matching __builtin_setjmp captured before the access,
        // so recovery is correct no matter which frame the fault occurred in and without invoking SEH unwinding (which
        // can abort when unwound from a vectored-handler-resumed context). The handler passes the buffer in the
        // first-argument register so the stub touches no thread-local itself. noinline gives it a stable address for
        // the handler to target.
        [[noreturn]] __attribute__((noinline)) void veh_perform_longjmp(void *env) noexcept
        {
            // __builtin_longjmp is typed void(void **, int); env points at the VehAccessGuard::env[5] buffer. The
            // explicit cast matches that signature (GCC accepts the bare void *, clang's frontend rejects it).
            __builtin_longjmp(static_cast<void **>(env), 1);
        }

        // Vectored exception handler, installed at the front of the list. It claims a fault only when the current
        // thread is inside a guarded access (the TLS slot is non-null), the code is one a guarded probe owns
        // (is_guarded_read_fault -- the same set the MSVC __except filters use), the record carries a faulting address,
        // and that address falls inside the foreign range being accessed. Every other fault is passed straight through,
        // so a host software exception reusing one of these codes, or any code running outside a guarded access, still
        // reaches the host's own handlers unchanged. On a claimed fault it redirects the thread into
        // veh_perform_longjmp, which reports the access as failed.
        LONG NTAPI dmk_veh_read_handler(PEXCEPTION_POINTERS info) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            if (slot == TLS_OUT_OF_INDEXES)
                return EXCEPTION_CONTINUE_SEARCH;

            auto *const guard = static_cast<VehAccessGuard *>(TlsGetValue(slot));
            if (guard == nullptr)
                return EXCEPTION_CONTINUE_SEARCH;

            const EXCEPTION_RECORD *const record = info->ExceptionRecord;
            if (!detail::is_guarded_read_fault(record->ExceptionCode))
                return EXCEPTION_CONTINUE_SEARCH;

            // A guarded foreign access can only fault with a hardware access-violation, guard-page or in-page-error,
            // all of which carry the faulting data address in ExceptionInformation[1]. Refuse to claim a record without
            // it: that rules out a host RaiseException reusing one of these NTSTATUS codes with no address from being
            // hijacked out of the host's control flow while a guarded access happens to be in flight on this thread.
            if (record->NumberParameters < 2)
                return EXCEPTION_CONTINUE_SEARCH;

            // Confine the claim to the foreign range this operation explicitly armed. A bug that faults outside the
            // range reaches the host's handlers instead of being silently swallowed.
            const std::uintptr_t fault_address = static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
            if (fault_address < guard->guard_lo || fault_address >= guard->guard_hi)
                return EXCEPTION_CONTINUE_SEARCH;
            guard->fault_address = fault_address;

            // If this was a guard-page fault, re-arm the host's fence before failing the read closed: the OS cleared
            // PAGE_GUARD when it dispatched, and leaving it cleared would let a retry read straight through the guard.
            rearm_guard_page_if_consumed(record);

            // Disarm before resuming so a fault inside the longjmp stub would pass through rather than recurse.
            TlsSetValue(slot, nullptr);

            // Resume the faulting thread in veh_perform_longjmp(env): instruction pointer to the stub, setjmp buffer in
            // the Win64 first-argument register (RCX). The stub is entered by an injected RIP change, not a CALL, so
            // the fault-point RSP is not the ABI-required call alignment; pre-align it (the stub reloads RSP from the
            // snapshot anyway, so this only protects the stub's own prologue) to keep the resume robust against future
            // codegen that might touch an aligned stack slot before the reload.
            CONTEXT *const ctx = info->ContextRecord;
            ctx->Rsp = (ctx->Rsp & ~static_cast<DWORD64>(15)) - 8;
            ctx->Rcx = reinterpret_cast<DWORD64>(&guard->env);
            ctx->Rip = reinterpret_cast<DWORD64>(&veh_perform_longjmp);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Install the handler once, lazily. Re-installable across a teardown cycle: release_guarded_engine removes it
        // and clears the handle, so a later guarded access or re-init installs a fresh one. Best-effort: if either
        // TlsAlloc or AddVectoredExceptionHandler fails (realistic only under exhaustion) the handle stays null;
        // byte-copy guards fall back to VirtualQuery plus ReadProcessMemory / WriteProcessMemory, while in-place region
        // guards fail closed without touching the foreign range.
        void ensure_veh_installed() noexcept
        {
            if (s_veh_handle.load(std::memory_order_acquire) != nullptr)
                return;

            std::lock_guard<std::mutex> lock(s_veh_mutex);
            if (s_veh_handle.load(std::memory_order_relaxed) != nullptr)
                return;
            if (s_veh_tls_index.load(std::memory_order_relaxed) == TLS_OUT_OF_INDEXES)
            {
                const DWORD slot = TlsAlloc();
                if (slot == TLS_OUT_OF_INDEXES)
                    return; // cannot guard; access paths take their fail-closed fallback
                s_veh_tls_index.store(slot, std::memory_order_release);
            }
            // First in the list (FirstHandler = 1): a guarded access always resolves through this handler before any
            // consumer VEH or frame-based SEH. Every fault that is not this thread's own in-flight guarded access is
            // passed through with EXCEPTION_CONTINUE_SEARCH, so being first never starves the host's handlers.
            void *const handle = AddVectoredExceptionHandler(1, dmk_veh_read_handler);
            s_veh_handle.store(handle, std::memory_order_release);
        }

        void remove_veh_handler() noexcept
        {
            std::lock_guard<std::mutex> lock(s_veh_mutex);
            void *const handle = s_veh_handle.load(std::memory_order_relaxed);
            if (handle == nullptr)
                return;
            // Stop new guarded accesses from taking the handler path, then wait for any access already committed to it
            // to finish before unregistering, so a fault cannot arrive after the handler is gone. The seq_cst store
            // pairs with the seq_cst stripe fetch_add / handle-load in the guarded access helpers (a Dekker protocol):
            // an access that observed a live handle is necessarily counted in its in-flight stripe before this store is
            // observed, so the seq_cst sum below cannot read zero while that access is still on the handler path.
            s_veh_handle.store(nullptr, std::memory_order_seq_cst);
            int spins = 0;
            while (veh_in_flight_total() > 0)
            {
                if (spins < 4096)
                    std::this_thread::yield();
                else
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                ++spins;
            }
            RemoveVectoredExceptionHandler(handle);
        }

        // Copy [src, src + len) into out under the vectored handler. The copy is a single rep movsb emitted as raw
        // inline assembly: inline asm is invisible to AddressSanitizer, which instruments only compiler-emitted loads,
        // so this deliberate cross-region read cannot raise an ASan false positive (the same reason the MSVC probe
        // copies via the
        // __movsb intrinsic). __builtin_setjmp records the recovery point; the guard is then published to this thread's
        // TLS slot so a read fault is claimable, and the handler longjmps back here so the setjmp expression returns
        // non-zero and the function reports failure. noinline keeps the read and its setjmp anchor in one
        // self-contained frame.
        __attribute__((noinline)) bool veh_guarded_copy(void *out, const void *src, std::size_t len) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            VehAccessGuard guard{};
            guard.guard_lo = reinterpret_cast<std::uintptr_t>(src);
            guard.guard_hi = guard.guard_lo + len;

            if (__builtin_setjmp(guard.env) != 0)
            {
                // Reached only when the handler longjmped here after swallowing a read fault; the handler already
                // cleared the TLS slot. Report the failure.
                return false;
            }

            // Arm after the setjmp captures env and before the read, so a fault in the rep movsb below is claimable
            // while a fault before the buffer is valid is not. TlsSetValue writes the thread's TLS array with no
            // allocation.
            TlsSetValue(slot, &guard);

            void *dst = out;
            const void *cur = src;
            std::size_t n = len;
            __asm__ __volatile__("rep movsb" : "+D"(dst), "+S"(cur), "+c"(n) : : "memory");

            TlsSetValue(slot, nullptr);
            return true;
        }

        __attribute__((noinline)) detail::GuardedWriteStatus
        veh_guarded_write(std::uintptr_t address, const void *source, std::size_t bytes) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            VehAccessGuard guard{};
            guard.guard_lo = address;
            guard.guard_hi = address + bytes;

            if (__builtin_setjmp(guard.env) != 0)
            {
                return guard.fault_address == address ? detail::GuardedWriteStatus::NotWritten
                                                      : detail::GuardedWriteStatus::MayBePartial;
            }

            TlsSetValue(slot, &guard);
            copy_with_fault_progress(reinterpret_cast<void *>(address), source, bytes);
            TlsSetValue(slot, nullptr);
            return detail::GuardedWriteStatus::Ok;
        }

        // Runs fn(ctx) with the vectored handler armed over [lo, hi). Used for in-place accesses where the operation is
        // not the simple rep movsb read that veh_guarded_copy performs (the writer wrapper and the scanner sweep).
        // __builtin_setjmp records the recovery point, the guard is published to this thread's TLS slot so a fault
        // inside [lo, hi) is claimable, and the handler longjmps back here so the setjmp expression returns non-zero
        // and the function reports failure. fn must touch only [lo, hi); a fault outside that range (e.g. a bug in fn)
        // is not claimed and reaches the host's handlers. fn is abandoned on a fault via __builtin_longjmp without
        // running destructors, so it must hold no resources that need unwinding -- the scanner sweep and write wrapper
        // use only POD locals. noinline keeps the setjmp anchor and the fn call in one self-contained frame.
        __attribute__((noinline)) bool veh_guarded_region(std::uintptr_t lo, std::uintptr_t hi,
                                                          void (*fn)(void *) noexcept, void *ctx) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            VehAccessGuard guard{};
            guard.guard_lo = lo;
            guard.guard_hi = hi;

            if (__builtin_setjmp(guard.env) != 0)
            {
                return false;
            }

            TlsSetValue(slot, &guard);
            fn(ctx);
            TlsSetValue(slot, nullptr);
            return true;
        }

        // Single entry point the MinGW read paths share. Rejects a wrapping or low source range first (a wrapped
        // addr + bytes would invert the handler's [guard_lo, guard_hi) check and let a real fault escape the guard).
        // Counts the read in the drain epoch around the path decision so a read on the guarded path is always visible
        // to release_guarded_engine's drain. Falls back to a VirtualQuery plus ReadProcessMemory copy when the handler
        // is unavailable.
        bool veh_read_bytes(std::uintptr_t addr, void *out, std::size_t bytes) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return false;

            ensure_veh_installed();

            const std::size_t stripe = veh_in_flight_stripe_index();
            s_veh_in_flight_stripes[stripe].count.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            const bool ok = armed ? veh_guarded_copy(out, reinterpret_cast<const void *>(addr), bytes)
                                  : virtualquery_validated_copy(addr, out, bytes);
            s_veh_in_flight_stripes[stripe].count.fetch_sub(1, std::memory_order_release);
            return ok;
        }

        detail::GuardedWriteStatus veh_write_bytes(std::uintptr_t addr, const void *source, std::size_t bytes) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return detail::GuardedWriteStatus::NotWritten;

            ensure_veh_installed();

            const std::size_t stripe = veh_in_flight_stripe_index();
            s_veh_in_flight_stripes[stripe].count.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            const detail::GuardedWriteStatus status =
                armed ? veh_guarded_write(addr, source, bytes) : virtualquery_validated_write(addr, source, bytes);
            s_veh_in_flight_stripes[stripe].count.fetch_sub(1, std::memory_order_release);
            return status;
        }
#endif // _WIN64
    } // namespace
#endif // !_MSC_VER

#if !defined(_MSC_VER) && defined(_WIN64)
    void detail::ensure_guarded_engine_installed() noexcept
    {
        ensure_veh_installed();
    }

    void detail::release_guarded_engine() noexcept
    {
        remove_veh_handler();
    }

    bool detail::run_guarded_region(std::uintptr_t lo, std::uintptr_t hi, void (*fn)(void *) noexcept,
                                    void *ctx) noexcept
    {
        // An empty or wrapping range has nothing to guard; run the access directly. A wrapped [lo, hi) would also
        // invert the handler's range check, the same input veh_read_bytes rejects up front.
        if (hi <= lo)
        {
            fn(ctx);
            return true;
        }

        ensure_veh_installed();

        // Count the call in the drain epoch around the path decision (mirroring veh_read_bytes) so a guarded access is
        // always visible to release_guarded_engine's drain.
        const std::size_t stripe = veh_in_flight_stripe_index();
        s_veh_in_flight_stripes[stripe].count.fetch_add(1, std::memory_order_seq_cst);
        const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
        bool completed = true;
        if (armed)
        {
            completed = veh_guarded_region(lo, hi, fn, ctx);
        }
        else
        {
            // Handler unavailable (install failed, realistic only under resource exhaustion): do not run an in-place
            // scan unguarded. The caller treats false as a skipped/faulted region and fails uniqueness-sensitive work
            // closed.
            completed = false;
        }
        s_veh_in_flight_stripes[stripe].count.fetch_sub(1, std::memory_order_release);
        return completed;
    }
#endif // !_MSC_VER && _WIN64

    bool detail::guarded_read_bytes(std::uintptr_t address, void *out, std::size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!out)
            return false;

        // Validate the COMPLETE half-open span [address, address + bytes) against the user-mode window
        // [USERSPACE_PTR_MIN, USERSPACE_PTR_MAX) before any read: a low-endpoint-and-wrap check alone would admit a
        // range that begins valid but ends at or across the upper ceiling into a first-chance exception.
        if (address < memory::USERSPACE_PTR_MIN || address + bytes < address ||
            address + bytes > memory::USERSPACE_PTR_MAX)
            return false;

#ifdef _MSC_VER
        __try
        {
#if defined(__SANITIZE_ADDRESS__)
            // Copy via __movsb (rep movsb) under ASan: MSVC routes std::memcpy through the ASan interceptor, which
            // inspects the source against ASan's shadow and false-positives on the foreign mapped memory this probe
            // legitimately reads (e.g. a module's data section during the RTTI walk). __movsb emits the copy inline
            // with no interceptable call. Release keeps std::memcpy.
            __movsb(static_cast<unsigned char *>(out), reinterpret_cast<const unsigned char *>(address), bytes);
#else
            std::memcpy(out, reinterpret_cast<const void *>(address), bytes);
#endif
            return true;
        }
        // Range-aware: swallow only a fault whose address lies in the foreign SOURCE span. A fault on the caller-owned
        // destination buffer (or any address outside [address, address + bytes)) is a caller/DMK defect and propagates.
        __except (guarded_range_fault_filter(GetExceptionInformation(), address, address + bytes))
        {
            return false;
        }
#else
        // MinGW lacks __try/__except. Read through the process-wide vectored fault guard: the success path is a single
        // rep movsb with no syscall, and any read fault across the span is swallowed and reported as failure.
        return veh_read_bytes(address, out, bytes);
#endif
    }

    namespace
    {
        // The raw fault-guarded store: no argument validation, no test-seam handling, just the contained copy. Shared
        // by guarded_write_bytes and its forward-copy seam so both take the exact same fault path.
        [[nodiscard]] detail::GuardedWriteStatus guarded_store_bytes(std::uintptr_t address, const void *source,
                                                                     std::size_t bytes) noexcept
        {
#ifdef _MSC_VER
            volatile std::uintptr_t fault_address = 0;
            __try
            {
                copy_with_fault_progress(reinterpret_cast<void *>(address), source, bytes);
                return detail::GuardedWriteStatus::Ok;
            }
            // Range-aware: a fault on the caller-owned SOURCE buffer (outside the destination span) is not contained.
            // Qualified: guarded_store_bytes lives in an anonymous namespace, from which unqualified lookup would not
            // reach detail::.
            __except (
                detail::guarded_range_fault_filter(GetExceptionInformation(), address, address + bytes, &fault_address))
            {
                return fault_address == address ? detail::GuardedWriteStatus::NotWritten
                                                : detail::GuardedWriteStatus::MayBePartial;
            }
#else
            // MinGW: write through the same guard/fallback split as guarded_read_bytes. The process-wide vectored guard
            // is used when available; otherwise it validates the destination and writes through WriteProcessMemory.
            return veh_write_bytes(address, source, bytes);
#endif
        }
    } // namespace

    detail::GuardedWriteStatus detail::guarded_write_bytes(std::uintptr_t address, const void *source,
                                                           std::size_t bytes) noexcept
    {
        if (bytes == 0)
            return GuardedWriteStatus::Ok;
        if (!source)
            return GuardedWriteStatus::NotWritten;

        // Validate the COMPLETE half-open destination span against the user-mode window before any store, matching
        // guarded_read_bytes: a low-endpoint-and-wrap check alone would admit a range ending at or across the ceiling.
        if (address < memory::USERSPACE_PTR_MIN || address + bytes < address ||
            address + bytes > memory::USERSPACE_PTR_MAX)
            return GuardedWriteStatus::NotWritten;

        const auto *const in = static_cast<const std::byte *>(source);

#if defined(DMK_ENABLE_TEST_SEAMS)
        if (s_seam_forward_copy)
        {
            std::size_t written = 0;
            for (; written < bytes; ++written)
            {
                if (guarded_store_bytes(address + written, in + written, 1) != GuardedWriteStatus::Ok)
                    break;
            }
            s_seam_last_prefix = written;
            if (written == bytes)
                return GuardedWriteStatus::Ok;
            return written == 0 ? GuardedWriteStatus::NotWritten : GuardedWriteStatus::MayBePartial;
        }
#endif

        const GuardedWriteStatus status = guarded_store_bytes(address, in, bytes);
#if defined(DMK_ENABLE_TEST_SEAMS)
        s_seam_last_prefix = status == GuardedWriteStatus::Ok ? bytes : 0;
#endif
        return status;
    }

    detail::ChainWalkOutcome detail::guarded_resolve_chain(Address base, const memory::ChainStep *steps,
                                                           std::size_t count, Address *trace,
                                                           std::size_t trace_cap) noexcept
    {
        ChainWalkOutcome outcome;

        // count == 0 is the identity walk: the leaf is base itself, with no hop to dereference or screen.
        if (count == 0)
        {
            outcome.address = base;
            outcome.ok = true;
            return outcome;
        }

        // One unified walk on both toolchains: each intermediate link is read through the range-aware guarded byte copy
        // (guarded_read_bytes), so the MSVC __except now screens the faulting address against the exact hop span the
        // same way the MinGW vectored handler always has, and a per-hop __try replaces the former single whole-loop
        // __try. checked_offset rejects a hop whose signed-offset addition wraps the address space, so a chain near the
        // top of the address space can no longer resolve a wrapped link or leaf as a plausible success.
        std::uintptr_t cur = base.raw();
        for (std::size_t i = 0; i + 1 < count; ++i)
        {
            std::uintptr_t link_address = 0;
            if (!checked_offset(cur, steps[i].offset, link_address))
            {
                outcome.fail_index = i;
                return outcome;
            }
            std::uintptr_t next = 0;
            if (!guarded_read_bytes(link_address, &next, sizeof(next)))
            {
                outcome.fail_index = i;
                return outcome;
            }
            // Screen the dereferenced link against this hop's floor and the user-mode ceiling: a torn or sentinel
            // pointer stops the walk at this hop before its value is used as the base of the next dereference.
            if (next < steps[i].min_valid.raw() || next >= memory::USERSPACE_PTR_MAX)
            {
                outcome.fail_index = i;
                return outcome;
            }
            if (trace != nullptr && i < trace_cap)
                trace[i] = Address{next};
            cur = next;
        }
        std::uintptr_t leaf = 0;
        if (!checked_offset(cur, steps[count - 1].offset, leaf) || leaf < memory::USERSPACE_PTR_MIN ||
            leaf >= memory::USERSPACE_PTR_MAX)
        {
            outcome.fail_index = count - 1;
            return outcome;
        }
        if (trace != nullptr && (count - 1) < trace_cap)
            trace[count - 1] = Address{leaf};
        outcome.address = Address{leaf};
        outcome.ok = true;
        return outcome;
    }

    namespace
    {
        // Releases each transaction holder and restores the newest surviving target, or the original protection when
        // no holder remains. Every page is attempted so one failure cannot strand unrelated pages.
        [[nodiscard]] bool restore_segments_locked(const detail::ProtectionSegment *segments, std::size_t count,
                                                   std::uint32_t &os_error) noexcept
        {
            auto *const ledger = protection_ledger();
            if (ledger == nullptr)
            {
                os_error = ERROR_NOT_ENOUGH_MEMORY;
                return false;
            }

            bool all_restored = true;
            const std::uintptr_t step = system_page_size();
            for (std::size_t i = 0; i < count; ++i)
            {
                std::uintptr_t run_begin = 0;
                std::uintptr_t run_end = 0;
                DWORD run_protection = 0;
                bool in_run = false;
                const auto restore_run = [&]() noexcept
                {
                    if (!in_run)
                    {
                        return;
                    }
                    DWORD previous = 0;
                    if (!change_page_protection(reinterpret_cast<LPVOID>(run_begin), run_end - run_begin,
                                                run_protection, &previous))
                    {
                        if (all_restored)
                        {
                            os_error = static_cast<std::uint32_t>(GetLastError());
                        }
                        all_restored = false;
                    }
                    else
                    {
                        for (std::uintptr_t page = run_begin; page < run_end; page += step)
                        {
                            const auto entry = ledger->find(page);
                            if (entry != ledger->end() && entry->second.empty())
                            {
                                ledger->erase(entry);
                            }
                        }
                    }
                    in_run = false;
                };

                const std::uintptr_t seg_end = segments[i].base + segments[i].size;
                for (std::uintptr_t page = page_floor(segments[i].base); page < seg_end; page += step)
                {
                    const auto entry = ledger->find(page);
                    DWORD desired = 0;
                    if (entry == ledger->end() ||
                        !entry->second.remove_holder(segments[i].transaction_id, nullptr, &desired))
                    {
                        restore_run();
                        if (all_restored)
                        {
                            os_error = ERROR_INVALID_DATA;
                        }
                        all_restored = false;
                        continue;
                    }

                    if (in_run && desired != run_protection)
                    {
                        restore_run();
                    }
                    if (!in_run)
                    {
                        run_begin = page;
                        run_protection = desired;
                        in_run = true;
                    }
                    run_end = page + step;
                }
                restore_run();
            }
            return all_restored;
        }
    } // namespace

    bool detail::restore_across_regions(const ProtectionSegment *segments, std::size_t count,
                                        std::uint32_t &os_error) noexcept
    {
        ProtectionLedgerLock lock;
        return restore_segments_locked(segments, count, os_error);
    }

    void detail::abandon_protection_tracking(const ProtectionSegment *segments, std::size_t count) noexcept
    {
        ProtectionLedgerLock lock;
        auto *const ledger = protection_ledger();
        if (ledger == nullptr)
        {
            return;
        }
        const std::uintptr_t step = system_page_size();
        for (std::size_t i = 0; i < count; ++i)
        {
            const std::uintptr_t seg_end = segments[i].base + segments[i].size;
            for (std::uintptr_t page = page_floor(segments[i].base); page < seg_end; page += step)
            {
                const auto entry = ledger->find(page);
                if (entry == ledger->end())
                {
                    continue;
                }
                DWORD released_target = 0;
                if (!entry->second.remove_holder(segments[i].transaction_id, &released_target, nullptr))
                {
                    continue;
                }
                // The released target becomes the baseline once all still-live overlapping guards leave.
                entry->second.original_protection = released_target;
                if (entry->second.empty())
                {
                    ledger->erase(entry);
                }
            }
        }
    }

    detail::ProtectionChangeOutcome detail::protect_across_regions(std::uintptr_t address, std::size_t bytes,
                                                                   std::uint32_t new_protection, ProtectionSegment *out,
                                                                   std::size_t out_cap,
                                                                   bool derive_writable_preserving_execute) noexcept
    {
        if (bytes == 0 || out == nullptr || out_cap == 0)
        {
            return {0, ProtectionChangeStatus::ChangeFailed, ERROR_INVALID_PARAMETER};
        }

        const std::uintptr_t span_end = address + bytes;
        if (span_end < address || address < memory::USERSPACE_PTR_MIN || span_end > memory::USERSPACE_PTR_MAX)
        {
            return {0, ProtectionChangeStatus::ChangeFailed, ERROR_INVALID_ADDRESS};
        }

        ProtectionLedgerLock lock;
        if (protection_ledger() == nullptr)
        {
            return {0, ProtectionChangeStatus::ChangeFailed, ERROR_NOT_ENOUGH_MEMORY};
        }

        std::size_t count = 0;
        const std::uint64_t transaction_id = next_transaction_id();
        const auto fail = [&](std::uint32_t change_error) noexcept -> ProtectionChangeOutcome
        {
            std::uint32_t rollback_error = 0;
            if (!restore_segments_locked(out, count, rollback_error))
            {
                return {0, ProtectionChangeStatus::RestoreFailed, rollback_error};
            }
            return {0, ProtectionChangeStatus::ChangeFailed, change_error};
        };

        std::uintptr_t cur = address;
        while (cur < span_end)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0)
            {
                return fail(static_cast<std::uint32_t>(GetLastError()));
            }

            // Clip this VirtualQuery region to the requested span. A region is page-aligned, so consecutive segments
            // meet exactly on a page boundary and VirtualProtect's page-rounding never pulls a neighbouring region's
            // protection along. A region size that overflows the address space is treated as reaching the span end.
            const std::uintptr_t region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t region_end = region_base + mbi.RegionSize;
            const std::uintptr_t effective_region_end = (region_end < region_base) ? span_end : region_end;
            const std::uintptr_t seg_end = (effective_region_end < span_end) ? effective_region_end : span_end;
            if (seg_end <= cur)
            {
                return fail(ERROR_INVALID_ADDRESS);
            }

            if (count >= out_cap)
            {
                return fail(ERROR_INSUFFICIENT_BUFFER);
            }

            // The new protection is either the caller's fixed value (ProtectGuard) or, for a patch, derived from this
            // region's own current protection so it gains write while preserving execute -- a data page never becomes
            // executable.
            const DWORD target = derive_writable_preserving_execute ? writable_protection_for(mbi.Protect)
                                                                    : static_cast<DWORD>(new_protection);

            const bool had_execute = (mbi.Protect & EXECUTE_PERMISSION_FLAGS) != 0;
            const std::uintptr_t page_lo = page_floor(cur);
            const std::uintptr_t page_hi = page_ceiling(seg_end);
            if (!ledger_acquire_pages(page_lo, page_hi, transaction_id, target, mbi.Protect))
            {
                return fail(ERROR_NOT_ENOUGH_MEMORY);
            }

            const std::size_t seg_size = static_cast<std::size_t>(seg_end - cur);
            DWORD old_protection = 0;
            if (!change_page_protection(reinterpret_cast<LPVOID>(cur), seg_size, target, &old_protection))
            {
                const std::uint32_t change_error = static_cast<std::uint32_t>(GetLastError());
                ledger_cancel_pages(page_lo, page_hi, transaction_id);
                return fail(change_error);
            }

            out[count].base = cur;
            out[count].size = seg_size;
            out[count].originally_executable = had_execute;
            out[count].transaction_id = transaction_id;
            ++count;
            cur = seg_end;
        }

        return {count, ProtectionChangeStatus::Ok, 0};
    }

    detail::PatchStatus detail::patch_bytes(std::uintptr_t address, const void *source, std::size_t bytes,
                                            std::uint32_t &os_error, bool flush_all_regions) noexcept
    {
        os_error = 0;

        // Make the target writable one protection region at a time, deriving each region's writable protection from its
        // own execute semantics so a DATA page never gains execute (a .rdata write stays non-executable) while a .text
        // patch keeps execute. The per-region walk also keeps a write straddling a protection seam from being restored
        // to a single flattened protection, and the transaction is serialized and ledger-tracked so an overlapping
        // guard over the same page still restores to the true original.
        ProtectionSegment segments[MAX_PROTECTION_SEGMENTS];
        const ProtectionChangeOutcome protection =
            protect_across_regions(address, bytes, 0, segments, MAX_PROTECTION_SEGMENTS, true);
        if (protection.status != ProtectionChangeStatus::Ok)
        {
            os_error = protection.os_error;
            return protection.status == ProtectionChangeStatus::RestoreFailed ? PatchStatus::ProtectionRestoreFailed
                                                                              : PatchStatus::ProtectionChangeFailed;
        }
        const std::size_t segment_count = protection.segment_count;

        // Route the store through the fault-guarded writer rather than a bare memcpy. The pages were just made
        // writable, so on a quiescent target this takes guarded_write_bytes' no-reprotect fast path. The guard is what
        // makes this noexcept host path survivable: if a page is reprotected or decommitted out from under the store (a
        // concurrent unmap of a code region being patched), the fault is contained and reported here -- a forward-copy
        // prefix may already have been written, reported below as WriteMayBePartial -- instead of terminating the host.
        const GuardedWriteStatus write_status = guarded_write_bytes(address, source, bytes);

        // An explicit code patch flushes every touched region. An ordinary data write flushes only a region that was
        // executable when this transaction began, so a read-only data write issues no flush.
        bool flush_ok = true;
        for (std::size_t i = 0; i < segment_count; ++i)
        {
            if (flush_all_regions || segments[i].originally_executable)
            {
                if (!flush_instruction_cache(segments[i].base, segments[i].size))
                {
                    flush_ok = false;
                }
            }
        }

        // Restore protection per region (ledger-refcounted so an overlapping transaction is not disturbed).
        std::uint32_t restore_error = 0;
        const bool restore_succeeded = restore_across_regions(segments, segment_count, restore_error);

        // Report the most severe outcome. A failed restore can leave a page writable-executable and outranks all;
        // then a partial copy (the patch did not fully land); then a stale instruction cache.
        if (!restore_succeeded)
        {
            os_error = restore_error;
            return PatchStatus::ProtectionRestoreFailed;
        }
        if (write_status == GuardedWriteStatus::NotWritten)
        {
            return PatchStatus::WriteFaulted;
        }
        if (write_status == GuardedWriteStatus::MayBePartial)
        {
            return PatchStatus::WriteMayBePartial;
        }
        if (!flush_ok)
        {
            return PatchStatus::InstructionFlushFailed;
        }
        return PatchStatus::Ok;
    }

    bool detail::flush_instruction_cache(std::uintptr_t address, std::size_t bytes) noexcept
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (s_seam_flush_fails)
        {
            return false;
        }
#endif
        return FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), bytes) != 0;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void detail::set_flush_failure_seam(bool fail) noexcept
    {
        s_seam_flush_fails = fail;
    }

    void detail::set_forward_copy_seam(bool enable) noexcept
    {
        s_seam_forward_copy = enable;
    }

    std::size_t detail::last_forward_copy_prefix() noexcept
    {
        return s_seam_last_prefix;
    }

    void detail::set_virtual_protect_failure_mask(std::uint64_t call_mask) noexcept
    {
        s_seam_virtual_protect_failures = call_mask;
        s_seam_virtual_protect_call = 0;
    }
#endif
} // namespace DetourModKit
