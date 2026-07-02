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
#if defined(_MSC_VER) && defined(__SANITIZE_ADDRESS__)
#include <intrin.h> // __movsb -- ASan-safe copy in the SEH probe read
#endif

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
        // Page-protection flag groups the VirtualQuery-validated fallbacks need to classify a region. The cache TU
        // keeps its own copy of these masks; the small duplication keeps this engine TU independent of the cache
        // subsystem.
        constexpr DWORD READ_PERMISSION_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD WRITE_PERMISSION_FLAGS =
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD NOACCESS_GUARD_FLAGS = PAGE_NOACCESS | PAGE_GUARD;
    } // namespace

#ifndef _MSC_VER
    // MinGW/GCC has no __try / __except, so the foreign-memory probes in this file cannot wrap their accesses in
    // frame-based SEH the way the MSVC paths do. A single process-wide vectored exception handler provides the
    // equivalent fault guard: each guarded access marks the foreign range it is about to touch in a thread-local slot,
    // and a fault inside that range is intercepted and turned into a clean failure instead of terminating the host. The
    // guarded path avoids a per-call VirtualQuery on successful terminal reads/writes and keeps stale state from
    // authorizing unguarded dereferences after a page is reprotected.
    namespace
    {
        // VirtualQuery-validated read. On x64 it is the fallback used only when the vectored handler could not be
        // installed; on a 32-bit MinGW build, where the handler's x64 register redirect is unavailable, it is the only
        // guard. The copy itself goes through ReadProcessMemory so a page that changes after the query fails as an API
        // result rather than as a user-mode fault.
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
        bool virtualquery_validated_write(std::uintptr_t addr, const void *source, std::size_t bytes) noexcept
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
                if ((mbi.Protect & WRITE_PERMISSION_FLAGS) == 0 || (mbi.Protect & NOACCESS_GUARD_FLAGS) != 0)
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
                if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<void *>(cur),
                                        static_cast<const std::byte *>(source) + copied, to_copy, &copied_now) ||
                    copied_now != to_copy)
                    return false;
                copied += to_copy;
            }
            return true;
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
        };

        std::mutex s_veh_mutex;
        std::atomic<void *> s_veh_handle{nullptr};
        // Process-lifetime TLS index, allocated once and reused across install/remove cycles (never freed so a removal
        // can never invalidate an index a concurrent access still holds). The handler reads it with an acquire load.
        std::atomic<DWORD> s_veh_tls_index{TLS_OUT_OF_INDEXES};
        // Count of accesses currently on the guarded path. release_guarded_engine drains this to zero before
        // unregistering the handler so a fault can never arrive after the handler is gone.
        std::atomic<int> s_veh_in_flight{0};

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
            // pairs with the seq_cst fetch_add / handle-load in the guarded access helpers (a Dekker protocol): an
            // access that observed a live handle is necessarily counted in s_veh_in_flight before this store is
            // observed.
            s_veh_handle.store(nullptr, std::memory_order_seq_cst);
            int spins = 0;
            while (s_veh_in_flight.load(std::memory_order_seq_cst) > 0)
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

            s_veh_in_flight.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            const bool ok = armed ? veh_guarded_copy(out, reinterpret_cast<const void *>(addr), bytes)
                                  : virtualquery_validated_copy(addr, out, bytes);
            s_veh_in_flight.fetch_sub(1, std::memory_order_release);
            return ok;
        }

        bool veh_write_bytes(std::uintptr_t addr, const void *source, std::size_t bytes) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return false;

            struct WriteContext
            {
                std::uintptr_t dst;
                const void *src;
                std::size_t bytes;
            } ctx{addr, source, bytes};

            const auto do_write = [](void *opaque) noexcept -> void
            {
                auto *context = static_cast<WriteContext *>(opaque);
                std::memcpy(reinterpret_cast<void *>(context->dst), context->src, context->bytes);
            };

            ensure_veh_installed();

            s_veh_in_flight.fetch_add(1, std::memory_order_seq_cst);
            const bool armed = s_veh_handle.load(std::memory_order_seq_cst) != nullptr;
            const bool ok = armed ? veh_guarded_region(addr, addr + bytes, do_write, &ctx)
                                  : virtualquery_validated_write(addr, source, bytes);
            s_veh_in_flight.fetch_sub(1, std::memory_order_release);
            return ok;
        }
#else // !_WIN64
      // 32-bit MinGW: the handler's recovery redirect rewrites x64 CONTEXT registers (Rcx/Rip) and the longjmp buffer
      // is x64-sized, so the vectored guard is x64-only. A guarded access here validates every region with VirtualQuery
      // before copying through ReadProcessMemory / WriteProcessMemory instead.
        bool veh_read_bytes(std::uintptr_t addr, void *out, std::size_t bytes) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return false;
            return virtualquery_validated_copy(addr, out, bytes);
        }

        bool veh_write_bytes(std::uintptr_t addr, const void *source, std::size_t bytes) noexcept
        {
            if (addr < memory::USERSPACE_PTR_MIN || addr + bytes < addr)
                return false;
            return virtualquery_validated_write(addr, source, bytes);
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
        s_veh_in_flight.fetch_add(1, std::memory_order_seq_cst);
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
        s_veh_in_flight.fetch_sub(1, std::memory_order_release);
        return completed;
    }
#endif // !_MSC_VER && _WIN64

    bool detail::guarded_read_bytes(std::uintptr_t address, void *out, std::size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!out || address < memory::USERSPACE_PTR_MIN)
            return false;

        // Overflow guard on (address + bytes); a wraparound source range can never be a valid mapped image.
        if (address + bytes < address)
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
        __except (is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW lacks __try/__except. Read through the process-wide vectored fault guard: the success path is a single
        // rep movsb with no syscall, and any read fault across the span is swallowed and reported as failure.
        return veh_read_bytes(address, out, bytes);
#endif
    }

    bool detail::guarded_write_bytes(std::uintptr_t address, const void *source, std::size_t bytes) noexcept
    {
        if (bytes == 0)
            return true;
        if (!source || address < memory::USERSPACE_PTR_MIN)
            return false;

        // Overflow guard on (address + bytes); a wraparound destination range can never be a valid mapped target.
        if (address + bytes < address)
            return false;

#ifdef _MSC_VER
        __try
        {
#if defined(__SANITIZE_ADDRESS__)
            // Copy via __movsb (rep movsb) under ASan for the same reason guarded_read_bytes does: MSVC routes
            // std::memcpy through the ASan interceptor, which false-positives on the foreign mapped memory this
            // primitive legitimately writes. __movsb emits the copy inline with no interceptable call.
            __movsb(reinterpret_cast<unsigned char *>(address), static_cast<const unsigned char *>(source), bytes);
#else
            std::memcpy(reinterpret_cast<void *>(address), source, bytes);
#endif
            return true;
        }
        __except (is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            return false;
        }
#else
        // MinGW: write through the same guard/fallback split as guarded_read_bytes. x64 uses the process-wide vectored
        // guard when available; otherwise, and on 32-bit builds, it validates the destination and writes through
        // WriteProcessMemory.
        return veh_write_bytes(address, source, bytes);
#endif
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

#ifdef _MSC_VER
        // current_hop tracks the hop whose dereference is in progress so the __except below can name the faulting hop:
        // a fault transfers control out of the loop, so the index must already be stored in a volatile the handler path
        // can read (a plain local's value at the fault point is indeterminate after the longjmp-like transfer).
        volatile std::size_t current_hop = 0;
        __try
        {
            std::uintptr_t cur = base.raw();
            for (std::size_t i = 0; i + 1 < count; ++i)
            {
                current_hop = i;
                const std::uintptr_t link_address = cur + static_cast<std::uintptr_t>(steps[i].offset);
                std::uintptr_t next = 0;
                std::memcpy(&next, reinterpret_cast<const void *>(link_address), sizeof(next));
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
            const std::uintptr_t leaf = cur + static_cast<std::uintptr_t>(steps[count - 1].offset);
            if (trace != nullptr && (count - 1) < trace_cap)
                trace[count - 1] = Address{leaf};
            outcome.address = Address{leaf};
            outcome.ok = true;
            return outcome;
        }
        __except (is_guarded_read_fault(GetExceptionCode()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
        {
            outcome.fail_index = current_hop;
            outcome.ok = false;
            return outcome;
        }
#else
        // MinGW: each intermediate link is read through the vectored-handler-guarded byte copy, which returns false on
        // fault; that and the plausibility screen both stop the walk at the current hop.
        std::uintptr_t cur = base.raw();
        for (std::size_t i = 0; i + 1 < count; ++i)
        {
            const std::uintptr_t link_address = cur + static_cast<std::uintptr_t>(steps[i].offset);
            std::uintptr_t next = 0;
            if (!guarded_read_bytes(link_address, &next, sizeof(next)))
            {
                outcome.fail_index = i;
                return outcome;
            }
            if (next < steps[i].min_valid.raw() || next >= memory::USERSPACE_PTR_MAX)
            {
                outcome.fail_index = i;
                return outcome;
            }
            if (trace != nullptr && i < trace_cap)
                trace[i] = Address{next};
            cur = next;
        }
        const std::uintptr_t leaf = cur + static_cast<std::uintptr_t>(steps[count - 1].offset);
        if (trace != nullptr && (count - 1) < trace_cap)
            trace[count - 1] = Address{leaf};
        outcome.address = Address{leaf};
        outcome.ok = true;
        return outcome;
#endif
    }

    detail::PatchStatus detail::patch_bytes(std::uintptr_t address, const void *source, std::size_t bytes,
                                            std::uint32_t &os_error) noexcept
    {
        os_error = 0;

        // Make the target writable. This is the slow path reached only after the no-reprotect guarded write faulted, so
        // the page is read-only or executable: request PAGE_EXECUTE_READWRITE so a code page keeps its execute right.
        DWORD old_protection = 0;
        if (!VirtualProtect(reinterpret_cast<LPVOID>(address), bytes, PAGE_EXECUTE_READWRITE, &old_protection))
        {
            os_error = static_cast<std::uint32_t>(GetLastError());
            return PatchStatus::ProtectionChangeFailed;
        }

        std::memcpy(reinterpret_cast<void *>(address), source, bytes);

        // The bytes are now modified, so the instruction-cache flush and the protection restore must both run. Restore
        // first so its outcome is known, but keep the flush unconditional: a code patch that changed bytes must flush
        // even if the restore fails, or a stale instruction stream could execute the old bytes.
        DWORD restored_from = 0;
        const bool restore_succeeded =
            VirtualProtect(reinterpret_cast<LPVOID>(address), bytes, old_protection, &restored_from) != FALSE;
        if (!restore_succeeded)
            os_error = static_cast<std::uint32_t>(GetLastError());

        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), bytes);

        return restore_succeeded ? PatchStatus::Ok : PatchStatus::ProtectionRestoreFailed;
    }
} // namespace DetourModKit
