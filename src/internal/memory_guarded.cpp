/**
 * @file memory_guarded.cpp
 * @brief This TU implements the shared fault-containment engine for guarded byte access.
 *
 * MSVC uses frame-based __try / __except filters here. Scanner TUs also use __try and route their filters through
 * guarded_range_fault_filter. MinGW/GCC uses a process-wide vectored exception handler here. A fault within an armed
 * foreign range returns a clean failure through __builtin_longjmp. This boundary keeps memory.hpp free of <windows.h>
 * and structured-exception constructs. The page-protection transaction ledger and the patch path that changes
 * protection live in memory_protect_ledger.cpp.
 */

#include "internal/memory_guarded.hpp"
#include "internal/memory_fault.hpp"

#include "DetourModKit/memory.hpp"

#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h> // __movsb provides an ASan-safe forward copy from foreign memory.
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>

namespace DetourModKit
{
    namespace
    {
        // Page-protection flag groups support the VirtualQuery-validated fallbacks. The cache TU keeps a separate copy
        // so this engine TU stays independent of the cache subsystem.
        constexpr DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD WRITE_PERMISSION_FLAGS =
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD NOACCESS_GUARD_FLAGS = PAGE_NOACCESS | PAGE_GUARD;

        // The STATUS_GUARD_PAGE_VIOLATION literal matches <winnt.h>. It needs no ntstatus.h include and cannot collide
        // with a platform macro of the same name.
        constexpr unsigned long GUARD_PAGE_FAULT_CODE = 0x80000001ul;

#if defined(DMK_ENABLE_TEST_SEAMS)
        std::atomic<bool> s_seam_guard_rearm_fails{false};
#endif

        // Re-arm a PAGE_GUARD page after the OS consumes the bit during fault dispatch. Otherwise the foreign guard
        // page loses its host fence and fails open. The read still fails closed, and the host's next access faults.
        // A restore failure is reported so the caller continues exception search instead of a fault claim.
        // Both the MinGW vectored handler and MSVC __except filters call this helper. VirtualQuery and VirtualProtect
        // neither allocate nor take a lock forbidden within exception dispatch.
        [[nodiscard]] bool rearm_guard_page_if_consumed(const EXCEPTION_RECORD *record) noexcept
        {
            if (record->ExceptionCode != GUARD_PAGE_FAULT_CODE)
            {
                return true;
            }
            if (record->NumberParameters < 2)
            {
                return false;
            }
            const auto fault_address = reinterpret_cast<LPVOID>(record->ExceptionInformation[1]);
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(fault_address, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT)
            {
                return false;
            }
            // The OS already cleared PAGE_GUARD, so mbi.Protect omits it. Add it back to restore the fence over the
            // page that contains the fault address.
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (s_seam_guard_rearm_fails.load(std::memory_order_relaxed))
            {
                return false;
            }
#endif
            DWORD previous = 0;
            return VirtualProtect(fault_address, 1, mbi.Protect | PAGE_GUARD, &previous) != 0;
        }
    } // namespace

    namespace
    {
        // Use an explicit forward copy so a fault at the first target byte proves that no later target byte was
        // written. The intrinsic/inline instruction also bypasses ASan's memcpy interceptor for deliberate
        // foreign-memory access.
        inline void copy_with_fault_progress(void *destination, const void *source, std::size_t bytes) noexcept
        {
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
            __movsb(static_cast<unsigned char *>(destination), static_cast<const unsigned char *>(source), bytes);
#else
            // Fixed-width copies compile to one destination store on both supported x64 toolchains. They preserve the
            // first-byte classification and avoid REP setup for the common scalar-write sizes.
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

        // Add a signed byte offset to an address and reject address-space wrap. A pointer-chain hop near either end
        // must not produce a wrapped link that modulo-2^64 addition reports as plausible.
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
            // For offset < 0, unsigned negation behavior is defined. Reject a magnitude that underflows past zero.
            const std::uintptr_t magnitude = static_cast<std::uintptr_t>(-(offset + 1)) + 1U;
            if (magnitude > base)
            {
                return false;
            }
            out = base - magnitude;
            return true;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        // Thread-local seams isolate one test's injection from another thread's guarded operation.
        thread_local bool s_seam_forward_copy = false;
        thread_local std::size_t s_seam_last_prefix = 0;
        // Process-wide lock-free counters avoid a first-touch emulated-TLS allocation inside loader-lock-safe guarded
        // paths. The overlap proof is single-threaded and resets them immediately before each observed call.
        std::atomic<std::size_t> s_seam_guarded_read_calls{0};
        std::atomic<std::size_t> s_seam_guarded_write_calls{0};
        std::atomic<std::size_t> s_seam_protection_calls{0};
        std::atomic<bool> s_seam_observe_guarded_access{false};
        static_assert(std::atomic<std::size_t>::is_always_lock_free);
        static_assert(std::atomic<bool>::is_always_lock_free);
#endif
    } // namespace

#ifdef _MSC_VER
    // Every MSVC guarded foreign access routes its __except through this shared frame-based SEH filter. Each route
    // uses the same fault set, address screen, and guard-page re-arm.
    // GetExceptionInformation() is valid only inside a filter expression, so call sites pass EXCEPTION_POINTERS in.
    long detail::guarded_range_fault_filter(
        EXCEPTION_POINTERS *info,
        std::uintptr_t lo,
        std::uintptr_t hi,
        volatile std::uintptr_t *fault_address_out
    ) noexcept
    {
        const EXCEPTION_RECORD *const record = info->ExceptionRecord;
        if (!detail::is_guarded_read_fault(record->ExceptionCode))
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // A guarded foreign access claims only a code with the data fault address in ExceptionInformation[1]. A host
        // RaiseException record without that address passes through, even if it reuses one of these NTSTATUS codes.
        if (record->NumberParameters < 2)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // Claim only a fault inside the declared foreign span. An unrelated defect or a caller-buffer fault reaches
        // the host handlers. The MinGW vectored handler uses the same rule.
        const std::uintptr_t fault_address = static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
        if (fault_address < lo || fault_address >= hi)
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (!rearm_guard_page_if_consumed(record))
        {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (fault_address_out != nullptr)
        {
            *fault_address_out = fault_address;
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }
#endif

#ifndef _MSC_VER
    // MinGW/GCC has no __try / __except. One process-wide vectored exception handler provides the equivalent fault
    // guard. Each guarded access records its foreign range in a thread slot. A fault in that range returns failure
    // instead of host termination.
    namespace
    {
        // This fallback applies whenever s_veh_handle is unavailable. ReadProcessMemory turns a page change after the
        // query into API failure rather than a user-mode fault.
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
                if (!ReadProcessMemory(
                        GetCurrentProcess(),
                        reinterpret_cast<const void *>(cur),
                        static_cast<std::byte *>(out) + copied,
                        to_copy,
                        &copied_now
                    ) ||
                    copied_now != to_copy)
                    return false;
                copied += to_copy;
            }
            return true;
        }

        // This fallback writes when no fault guard is available. It never changes page protection (a non-writable
        // protection fails closed) and copies through WriteProcessMemory.
        detail::GuardedWriteStatus
        virtualquery_validated_write(std::uintptr_t addr, const void *source, std::size_t bytes) noexcept
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
                const bool ok = WriteProcessMemory(
                                    GetCurrentProcess(),
                                    reinterpret_cast<void *>(cur),
                                    static_cast<const std::byte *>(source) + copied,
                                    to_copy,
                                    &copied_now
                                ) != 0;
                copied += copied_now;
                if (!ok || copied_now != to_copy)
                    return copied == 0 ? detail::GuardedWriteStatus::NotWritten
                                       : detail::GuardedWriteStatus::MayBePartial;
            }
            return detail::GuardedWriteStatus::Ok;
        }

#if defined(_WIN64)
        // Each guarded access publishes its stack record to the thread's Win32 TLS slot. Nested accesses preserve and
        // restore the prior slot value. MinGW lowers thread_local to __emutls_get_address, which allocates and locks
        // on first access. Exception dispatch forbids those operations. TlsGetValue is valid in that context.
        struct VehAccessGuard
        {
            void *env[5];            // Stores the __builtin_setjmp buffer for longjmp under the five-word GCC ABI.
            std::uintptr_t guard_lo; // Marks the first byte of the foreign range.
            std::uintptr_t guard_hi; // Marks one byte past the foreign range.
            volatile std::uintptr_t fault_address;
        };

        std::mutex s_veh_mutex;
        std::atomic<void *> s_veh_handle{nullptr};
        // The process-lifetime TLS index never becomes free. Handler removal cannot invalidate an index held by a
        // concurrent access.
        std::atomic<DWORD> s_veh_tls_index{TLS_OUT_OF_INDEXES};

        // Cache-line-padded counters stripe current guarded-path accesses and avoid contention on one global line.
        // The release_guarded_engine function drains the sum to zero before handler removal. The handle-null store,
        // stripe increment, and drain loads use seq_cst under Dekker. An access that observes a live handle enters the
        // count before the drain observes zero.
        constexpr std::size_t VEH_IN_FLIGHT_STRIPE_COUNT = 64;

        // alignas(64) needs no MSVC C4324 suppression here. The #ifndef _MSC_VER region hides this padded struct from
        // every MSVC build.
        struct alignas(64) VehInFlightStripe
        {
            std::atomic<int> count{0};
        };

        std::array<VehInFlightStripe, VEH_IN_FLIGHT_STRIPE_COUNT> s_veh_in_flight_stripes{};

        // A stable Win32 thread ID selects this thread's in-flight stripe. The same stripe receives entry and exit,
        // so its count stays nonnegative. GetCurrentThreadId allocates nothing and takes no lock, so loader lock
        // permits it. A stripe collision adds contention but cannot cause a miscount.
        [[nodiscard]] inline std::size_t veh_in_flight_stripe_index() noexcept
        {
            const std::uint64_t mixed = static_cast<std::uint64_t>(GetCurrentThreadId()) * 0x9E3779B97F4A7C15ULL;
            return static_cast<std::size_t>(mixed >> 48) % VEH_IN_FLIGHT_STRIPE_COUNT;
        }

        // The sum of all in-flight stripes equals the guarded accesses on the handler path. After publication of
        // s_veh_handle = nullptr, remove_veh_handler waits for this sum to reach zero under seq_cst.
        [[nodiscard]] inline int veh_in_flight_total() noexcept
        {
            int total = 0;
            for (const VehInFlightStripe &stripe : s_veh_in_flight_stripes)
            {
                total += stripe.count.load(std::memory_order_seq_cst);
            }
            return total;
        }

        // Return true when this thread already executes a guarded access. A nested access must not call
        // ensure_veh_installed. A wait on s_veh_mutex deadlocks with remove_veh_handler, which holds that mutex until
        // this thread exits. The omitted install loses nothing. After teardown, the seq_cst handle load routes a
        // nested access to the fallback.
        [[nodiscard]] inline bool inside_guarded_access() noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            if (slot == TLS_OUT_OF_INDEXES)
                return false;
            return TlsGetValue(slot) != nullptr;
        }

        // The handler redirects a thread with a fault into this recovery stub. __builtin_longjmp restores the paired
        // __builtin_setjmp snapshot without an SEH stack unwind. That unwind can abort from a vectored-handler resume
        // context. noinline gives the handler a stable target address.
        [[noreturn]] __attribute__((noinline)) void veh_perform_longjmp(void *env) noexcept
        {
            // __builtin_longjmp has type void(void **, int). env points to the VehAccessGuard::env[5] buffer. The
            // explicit cast matches that signature. GCC accepts bare void *, but the Clang front end rejects it.
            __builtin_longjmp(static_cast<void **>(env), 1);
        }

        // The vectored exception handler claims only faults from a guarded access. The code must belong to the same
        // set as the MSVC filters, and the record must contain an address within the armed foreign range. Every other
        // fault passes through. A claimed fault redirects the thread to veh_perform_longjmp, which reports access
        // failure.
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

            // Refuse a record without a fault address. A host RaiseException call that reuses one of these NTSTATUS
            // codes must stay in host control flow.
            if (record->NumberParameters < 2)
                return EXCEPTION_CONTINUE_SEARCH;

            // Confine the claim to the armed foreign range. A defect outside it reaches the host handlers.
            const std::uintptr_t fault_address = static_cast<std::uintptr_t>(record->ExceptionInformation[1]);
            if (fault_address < guard->guard_lo || fault_address >= guard->guard_hi)
                return EXCEPTION_CONTINUE_SEARCH;
            // Re-arm the host fence before the read returns a closed failure. See rearm_guard_page_if_consumed.
            if (!rearm_guard_page_if_consumed(record))
                return EXCEPTION_CONTINUE_SEARCH;
            guard->fault_address = fault_address;

            // Disarm before resume so a fault inside the longjmp stub passes through instead of a recursive claim.
            TlsSetValue(slot, nullptr);

            // Resume the thread in veh_perform_longjmp(env). Set RIP to the stub and place the setjmp buffer in RCX.
            // Entry uses an injected RIP change instead of CALL. Pre-align the fault-point RSP for the stub prologue.
            // The stub reloads RSP from the snapshot.
            CONTEXT *const ctx = info->ContextRecord;
            ctx->Rsp = (ctx->Rsp & ~static_cast<DWORD64>(15)) - 8;
            ctx->Rcx = reinterpret_cast<DWORD64>(&guard->env);
            ctx->Rip = reinterpret_cast<DWORD64>(&veh_perform_longjmp);
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Install the handler on first demand and permit installation after teardown. On failure, the null handle
        // routes byte-copy guards to the VirtualQuery fallback. In-place region guards fail closed before access to
        // the foreign range.
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
                    return; // Guard setup failed. Access paths use their fail-closed fallback.
                s_veh_tls_index.store(slot, std::memory_order_release);
            }
            // This handler is first, so a guarded access resolves through it before any consumer VEH or SEH.
            // Every other fault passes through, so first position never starves the host handlers.
            void *const handle = AddVectoredExceptionHandler(1, dmk_veh_read_handler);
            s_veh_handle.store(handle, std::memory_order_release);
        }

        void remove_veh_handler() noexcept
        {
            std::lock_guard<std::mutex> lock(s_veh_mutex);
            void *const handle = s_veh_handle.load(std::memory_order_relaxed);
            if (handle == nullptr)
                return;
            // Stop new guarded accesses, then wait for each access already committed to the handler path. No fault can
            // arrive after handler removal. The seq_cst store pairs with the helpers' seq_cst stripe fetch_add and
            // handle load under Dekker. The sum below cannot read zero while such an access is live.
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

        // Copy [src, src + len) into out under the vectored handler. Raw inline asm hides the single rep movsb from
        // ASan, so this deliberate cross-region read cannot cause a false positive. The MSVC probe uses __movsb for
        // the same reason. __builtin_setjmp records the recovery point. The handler uses longjmp so the setjmp
        // expression returns nonzero. noinline keeps the read and its anchor in one frame.
        __attribute__((noinline)) bool
        veh_guarded_copy(void *out, const void *src, std::size_t len, volatile std::uintptr_t *fault_out) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            // Read before the setjmp so it survives the longjmp return.
            void *const enclosing = TlsGetValue(slot);
            VehAccessGuard guard{};
            guard.guard_lo = reinterpret_cast<std::uintptr_t>(src);
            guard.guard_hi = guard.guard_lo + len;

            if (__builtin_setjmp(guard.env) != 0)
            {
                // This path runs only after the handler uses longjmp to contain a read fault.
                TlsSetValue(slot, enclosing);
                if (fault_out != nullptr)
                {
                    *fault_out = guard.fault_address;
                }
                return false;
            }

            // Arm after the setjmp captures env and before the read.
            TlsSetValue(slot, &guard);

            void *dst = out;
            const void *cur = src;
            std::size_t n = len;
            __asm__ __volatile__("rep movsb" : "+D"(dst), "+S"(cur), "+c"(n) : : "memory");

            TlsSetValue(slot, enclosing);
            return true;
        }

        __attribute__((noinline)) detail::GuardedWriteStatus
        veh_guarded_write(std::uintptr_t address, const void *source, std::size_t bytes) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            void *const enclosing = TlsGetValue(slot);
            VehAccessGuard guard{};
            guard.guard_lo = address;
            guard.guard_hi = address + bytes;

            if (__builtin_setjmp(guard.env) != 0)
            {
                TlsSetValue(slot, enclosing);
                return guard.fault_address == address ? detail::GuardedWriteStatus::NotWritten
                                                      : detail::GuardedWriteStatus::MayBePartial;
            }

            TlsSetValue(slot, &guard);
            copy_with_fault_progress(reinterpret_cast<void *>(address), source, bytes);
            TlsSetValue(slot, enclosing);
            return detail::GuardedWriteStatus::Ok;
        }

        // Run fn(ctx) with the vectored handler armed over [lo, hi) for an in-place access. fn must touch only that
        // range because the handler does not claim other faults. A claimed fault abandons fn without destructor calls.
        // fn must hold no resource whose release depends on stack unwind. It must not block indefinitely because
        // teardown waits for its in-flight stripe count. fn can call a nested guarded access outside [lo, hi), and the
        // nested wrapper restores this guard after that call returns.
        __attribute__((noinline)) bool
        veh_guarded_region(std::uintptr_t lo, std::uintptr_t hi, void (*fn)(void *) noexcept, void *ctx) noexcept
        {
            const DWORD slot = s_veh_tls_index.load(std::memory_order_acquire);
            void *const enclosing = TlsGetValue(slot);
            VehAccessGuard guard{};
            guard.guard_lo = lo;
            guard.guard_hi = hi;

            if (__builtin_setjmp(guard.env) != 0)
            {
                TlsSetValue(slot, enclosing);
                return false;
            }

            TlsSetValue(slot, &guard);
            fn(ctx);
            TlsSetValue(slot, enclosing);
            return true;
        }

        // This entry point serves all MinGW read paths. Reject a source range below the floor or across address-space
        // wrap. A wrapped range inverts the handler guard check and lets a real fault escape. Count the read in the
        // drain epoch around the path choice. Use the VirtualQuery copy when the handler is unavailable.
        bool
        veh_read_bytes(std::uintptr_t addr, void *out, std::size_t bytes, volatile std::uintptr_t *fault_out) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return false;

            if (!inside_guarded_access())
            {
                ensure_veh_installed();
            }

            const std::size_t stripe = veh_in_flight_stripe_index();
            s_veh_in_flight_stripes[stripe].count.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            // The VirtualQuery fallback never faults and has no fault address to report into fault_out.
            const bool ok = armed ? veh_guarded_copy(out, reinterpret_cast<const void *>(addr), bytes, fault_out)
                                  : virtualquery_validated_copy(addr, out, bytes);
            s_veh_in_flight_stripes[stripe].count.fetch_sub(1, std::memory_order_release);
            return ok;
        }

        detail::GuardedWriteStatus veh_write_bytes(std::uintptr_t addr, const void *source, std::size_t bytes) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return detail::GuardedWriteStatus::NotWritten;

            if (!inside_guarded_access())
            {
                ensure_veh_installed();
            }

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

    bool
    detail::run_guarded_region(std::uintptr_t lo, std::uintptr_t hi, void (*fn)(void *) noexcept, void *ctx) noexcept
    {
        // An empty range or one with address-space wrap has nothing to guard. A wrapped [lo, hi) inverts the handler
        // check.
        if (hi <= lo)
        {
            fn(ctx);
            return true;
        }

        if (!inside_guarded_access())
        {
            ensure_veh_installed();
        }

        // Count the call in the drain epoch around the path choice, as veh_read_bytes does.
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
            // The handler is unavailable. Do not run an in-place scan without a guard. The caller treats false as a
            // skipped or faulted region and closes uniqueness-sensitive work.
            completed = false;
        }
        s_veh_in_flight_stripes[stripe].count.fetch_sub(1, std::memory_order_release);
        return completed;
    }
#endif // !_MSC_VER && _WIN64

    bool detail::guarded_read_bytes(
        std::uintptr_t address,
        void *out,
        std::size_t bytes,
        volatile std::uintptr_t *fault_address_out
    ) noexcept
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (s_seam_observe_guarded_access.load(std::memory_order_relaxed))
        {
            s_seam_guarded_read_calls.fetch_add(1, std::memory_order_relaxed);
        }
#endif
        if (bytes == 0)
            return true;
        if (!out)
            return false;

        // Validate the complete half-open span [address, address + bytes) against the user-mode window before any
        // read. A low-endpoint and wrap check alone admits a range that reaches the upper ceiling and causes a
        // first-chance exception.
        if (address < memory::USERSPACE_PTR_MIN || address + bytes < address ||
            address + bytes > memory::USERSPACE_PTR_MAX)
            return false;

#ifdef _MSC_VER
        __try
        {
#if defined(__SANITIZE_ADDRESS__)
            // Under ASan, MSVC routes std::memcpy through an interceptor that reports this valid foreign-memory probe
            // as a false positive. Release keeps std::memcpy.
            __movsb(static_cast<unsigned char *>(out), reinterpret_cast<const unsigned char *>(address), bytes);
#else
            std::memcpy(out, reinterpret_cast<const void *>(address), bytes);
#endif
            return true;
        }
        // Swallow only a fault whose address lies in the foreign source span. A caller-buffer fault or any address
        // outside [address, address + bytes) identifies a caller or DMK defect and propagates.
        __except (guarded_range_fault_filter(GetExceptionInformation(), address, address + bytes, fault_address_out))
        {
            return false;
        }
#else
        // On MinGW, read through the vectored fault guard. The success path uses one rep movsb and no system call.
        return veh_read_bytes(address, out, bytes, fault_address_out);
#endif
    }

    namespace
    {
        // The raw fault-guarded store performs only the contained copy, with no argument validation or test-seam work.
        // The guarded_write_bytes entry point and its forward-copy seam share this store and use the same fault path.
        [[nodiscard]] detail::GuardedWriteStatus
        guarded_store_bytes(std::uintptr_t address, const void *source, std::size_t bytes) noexcept
        {
#ifdef _MSC_VER
            volatile std::uintptr_t fault_address = 0;
            __try
            {
                copy_with_fault_progress(reinterpret_cast<void *>(address), source, bytes);
                return detail::GuardedWriteStatus::Ok;
            }
            // Do not contain a fault on the caller-owned source buffer. Qualify detail:: because unqualified lookup
            // from this anonymous namespace does not reach it.
            __except (
                detail::guarded_range_fault_filter(GetExceptionInformation(), address, address + bytes, &fault_address)
            )
            {
                return fault_address == address ? detail::GuardedWriteStatus::NotWritten
                                                : detail::GuardedWriteStatus::MayBePartial;
            }
#else
            // On MinGW, write through the same guard and fallback split as guarded_read_bytes.
            return veh_write_bytes(address, source, bytes);
#endif
        }
    } // namespace

    detail::GuardedWriteStatus
    detail::guarded_write_bytes(std::uintptr_t address, const void *source, std::size_t bytes) noexcept
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (s_seam_observe_guarded_access.load(std::memory_order_relaxed))
        {
            s_seam_guarded_write_calls.fetch_add(1, std::memory_order_relaxed);
        }
#endif
        if (bytes == 0)
            return GuardedWriteStatus::Ok;
        if (!source)
            return GuardedWriteStatus::NotWritten;

        // Validate the complete half-open destination span against the user-mode window before any store. As in
        // guarded_read_bytes, a low-endpoint and wrap check alone admits a range that reaches the ceiling.
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

    namespace
    {
        struct CompareExchangeWordContext
        {
            std::uintptr_t address{0};
            std::uintptr_t expected{0};
            std::uintptr_t replacement{0};
            std::uintptr_t observed{0};
        };

        void compare_exchange_word(void *raw_context) noexcept
        {
            auto *const context = static_cast<CompareExchangeWordContext *>(raw_context);
            static_assert(sizeof(LONG64) == sizeof(std::uintptr_t));
            const LONG64 observed = ::InterlockedCompareExchange64(
                reinterpret_cast<volatile LONG64 *>(context->address),
                std::bit_cast<LONG64>(context->replacement),
                std::bit_cast<LONG64>(context->expected)
            );
            context->observed = std::bit_cast<std::uintptr_t>(observed);
        }
    } // namespace

    bool detail::guarded_compare_exchange_word(
        std::uintptr_t address,
        std::uintptr_t expected,
        std::uintptr_t replacement
    ) noexcept
    {
        constexpr std::size_t word_bytes = sizeof(std::uintptr_t);
        if (address % alignof(std::uintptr_t) != 0 || address < memory::USERSPACE_PTR_MIN ||
            address + word_bytes < address || address + word_bytes > memory::USERSPACE_PTR_MAX)
        {
            return false;
        }

        CompareExchangeWordContext context{address, expected, replacement, 0};
#ifdef _MSC_VER
        __try
        {
            compare_exchange_word(&context);
        }
        __except (guarded_range_fault_filter(GetExceptionInformation(), address, address + word_bytes))
        {
            return false;
        }
#else
        if (!run_guarded_region(address, address + word_bytes, &compare_exchange_word, &context))
        {
            return false;
        }
#endif
        return context.observed == expected;
    }

    detail::ChainWalkOutcome detail::guarded_resolve_chain(
        Address base,
        const memory::ChainStep *steps,
        std::size_t count,
        Address *trace,
        std::size_t trace_cap
    ) noexcept
    {
        ChainWalkOutcome outcome;

        // When count == 0, the identity walk returns base itself and performs no dereference or screen.
        if (count == 0)
        {
            outcome.address = base;
            outcome.ok = true;
            return outcome;
        }

        // Both toolchains use one walk. The range-aware guarded byte copy reads each link. checked_offset rejects a
        // hop when signed offset addition wraps the address space.
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
            // Screen the dereferenced link against this hop's floor and the user-mode ceiling before use as the next
            // dereference base.
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

#if defined(DMK_ENABLE_TEST_SEAMS)
    void detail::note_protection_call_for_test() noexcept
    {
        if (s_seam_observe_guarded_access.load(std::memory_order_relaxed))
        {
            s_seam_protection_calls.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void detail::reset_guarded_access_observation_for_test() noexcept
    {
        s_seam_guarded_read_calls.store(0, std::memory_order_relaxed);
        s_seam_guarded_write_calls.store(0, std::memory_order_relaxed);
        s_seam_protection_calls.store(0, std::memory_order_relaxed);
        s_seam_observe_guarded_access.store(true, std::memory_order_release);
    }

    detail::GuardedAccessObservation detail::guarded_access_observation_for_test() noexcept
    {
        return GuardedAccessObservation{
            s_seam_guarded_read_calls.load(std::memory_order_relaxed),
            s_seam_guarded_write_calls.load(std::memory_order_relaxed),
            s_seam_protection_calls.load(std::memory_order_relaxed)
        };
    }

    void detail::stop_guarded_access_observation_for_test() noexcept
    {
        s_seam_observe_guarded_access.store(false, std::memory_order_release);
    }

    void detail::set_forward_copy_seam(bool enable) noexcept
    {
        s_seam_forward_copy = enable;
    }

    std::size_t detail::last_forward_copy_prefix() noexcept
    {
        return s_seam_last_prefix;
    }

    void detail::set_guard_rearm_failure_seam(bool fail) noexcept
    {
        s_seam_guard_rearm_fails.store(fail, std::memory_order_relaxed);
    }
#endif
} // namespace DetourModKit
