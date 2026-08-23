/**
 * @file memory_protect_ledger.cpp
 * @brief This TU owns the page-protection transaction ledger and the patch path that changes protection.
 *
 * The fault-containment engine (SEH/VEH guarded byte access) stays in memory_guarded.cpp. patch_bytes reaches its
 * guarded copy through the detail:: seam in internal/memory_guarded.hpp. The ledger serializes every protection
 * transaction. Guards that overlap restore the true original protection.
 */

#include "internal/memory_guarded.hpp"

#include "DetourModKit/memory.hpp"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>
#include <unordered_map>
#include <vector>

namespace DetourModKit
{
    namespace
    {
        // These page protections carry execute. A writable protection derived for a patch must preserve execute for a
        // code region and must NOT add it to a data region.
        constexpr DWORD EXECUTE_PERMISSION_FLAGS =
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        // Derive writable protection from the current value. An executable region keeps execute, so DEP permits its
        // next execution. A data page never gains execute.
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

        struct PageProtectionHolder
        {
            std::uint64_t transaction_id = 0;
            DWORD target_protection = 0;
        };

        // The first holder stays inline because disjoint guards are common. Additional holders preserve acquisition
        // order so removal of an inner transaction restores the newest live target.
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

            [[nodiscard]] bool
            remove_holder(std::uint64_t transaction_id, DWORD *removed_target, DWORD *desired_protection) noexcept
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
                    const auto holder = std::find_if(
                        newer_holders.begin(),
                        newer_holders.end(),
                        [transaction_id](const PageProtectionHolder &candidate) noexcept
                        { return candidate.transaction_id == transaction_id; }
                    );
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

        [[nodiscard]] bool ledger_acquire_pages(
            std::uintptr_t page_lo,
            std::uintptr_t page_hi,
            std::uint64_t transaction_id,
            DWORD target_protection,
            DWORD current_original
        ) noexcept
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
        // Thread-local seams isolate one test's injection from another thread's guarded operation.
        thread_local bool s_seam_flush_fails = false;
        thread_local detail::InstructionFlushObservation s_seam_flush_observation{};
        thread_local bool s_seam_patch_write_not_written = false;
        thread_local std::uint64_t s_seam_virtual_protect_failures = 0;
        thread_local std::size_t s_seam_virtual_protect_call = 0;
#endif

        [[nodiscard]] bool
        change_page_protection(LPVOID address, SIZE_T bytes, DWORD protection, DWORD *previous) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            detail::note_protection_call_for_test();
            const std::size_t call = s_seam_virtual_protect_call++;
            if (call < 64 && (s_seam_virtual_protect_failures & (std::uint64_t{1} << call)) != 0)
            {
                SetLastError(ERROR_ACCESS_DENIED);
                return false;
            }
#endif
            return VirtualProtect(address, bytes, protection, previous) != 0;
        }

        // Release each transaction holder and restore the newest live target, or the original protection when no
        // holder remains. Attempt every page so one failure cannot strand unrelated pages.
        [[nodiscard]] bool restore_segments_locked(
            const detail::ProtectionSegment *segments,
            std::size_t count,
            std::uint32_t &os_error
        ) noexcept
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
                    if (!change_page_protection(
                            reinterpret_cast<LPVOID>(run_begin),
                            run_end - run_begin,
                            run_protection,
                            &previous
                        ))
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
    } // anonymous namespace

    bool detail::restore_across_regions(
        const ProtectionSegment *segments,
        std::size_t count,
        std::uint32_t &os_error
    ) noexcept
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
                // The released target becomes the baseline after all live guards over the same range leave.
                entry->second.original_protection = released_target;
                if (entry->second.empty())
                {
                    ledger->erase(entry);
                }
            }
        }
    }

    detail::ProtectionChangeOutcome detail::protect_across_regions(
        std::uintptr_t address,
        std::size_t bytes,
        std::uint32_t new_protection,
        ProtectionSegment *out,
        std::size_t out_cap,
        bool derive_writable_preserving_execute
    ) noexcept
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

            // Clip this region to the span. Page-aligned regions meet exactly on a page boundary, so VirtualProtect
            // cannot include a neighbor. Treat region-size overflow as the span end.
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

            // Use either the caller's fixed ProtectGuard value or a patch value derived from this region's protection.
            // A data page never becomes executable.
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

    detail::PatchStatus detail::patch_bytes(
        std::uintptr_t address,
        const void *source,
        std::size_t bytes,
        std::uint32_t &os_error,
        bool flush_all_regions
    ) noexcept
    {
        os_error = 0;

        // Make the target writable one protection region at a time. A data page never gains execute. A cross-region
        // write never restores one flat protection. The transaction ledger lets a guard over the same page restore
        // the true original protection.
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

        // Route the store through the fault-guarded writer instead of bare memcpy. If a page loses access during the
        // store, the writer contains and reports the fault, possibly as WriteMayBePartial. The host stays alive.
#if defined(DMK_ENABLE_TEST_SEAMS)
        const GuardedWriteStatus write_status = s_seam_patch_write_not_written
                                                    ? GuardedWriteStatus::NotWritten
                                                    : guarded_write_bytes(address, source, bytes);
#else
        const GuardedWriteStatus write_status = guarded_write_bytes(address, source, bytes);
#endif

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

        // Restore protection per region. The transaction ledger preserves any live transaction over the same range.
        std::uint32_t restore_error = 0;
        const bool restore_succeeded = restore_across_regions(segments, segment_count, restore_error);

        // Report the most severe outcome. A failed restore can leave a page writable-executable and outranks all
        // other failures. A partial copy ranks next, followed by a stale instruction cache.
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
        s_seam_flush_observation.address = address;
        s_seam_flush_observation.bytes = bytes;
        ++s_seam_flush_observation.call_count;
        if (s_seam_flush_fails)
        {
            s_seam_flush_observation.succeeded = false;
            return false;
        }
#endif
        const bool succeeded =
            FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), bytes) != 0;
#if defined(DMK_ENABLE_TEST_SEAMS)
        s_seam_flush_observation.succeeded = succeeded;
#endif
        return succeeded;
    }

    void detail::flush_if_executable(std::uintptr_t address, std::size_t bytes) noexcept
    {
        // A request can start in data and cross an executable region. Walk every covered region and flush after the
        // first executable region appears. An all-data request issues nothing.
        const std::uintptr_t span_end = address + bytes;
        if (span_end <= address)
        {
            return;
        }
        for (std::uintptr_t cur = address; cur < span_end;)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) == 0)
            {
                return;
            }
            if ((mbi.Protect & EXECUTE_PERMISSION_FLAGS) != 0)
            {
                (void)flush_instruction_cache(address, bytes);
                return;
            }
            // Treat region-size overflow as the span end. A region that does not advance past the cursor ends the walk
            // instead of an endless loop.
            const std::uintptr_t region_end = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (region_end <= cur)
            {
                return;
            }
            cur = region_end;
        }
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void detail::set_flush_failure_seam(bool fail) noexcept
    {
        s_seam_flush_fails = fail;
    }

    void detail::reset_instruction_flush_observation_for_test() noexcept
    {
        s_seam_flush_observation = {};
    }

    detail::InstructionFlushObservation detail::instruction_flush_observation_for_test() noexcept
    {
        return s_seam_flush_observation;
    }

    void detail::set_patch_write_not_written_for_test(bool fail) noexcept
    {
        s_seam_patch_write_not_written = fail;
    }

    void detail::set_virtual_protect_failure_mask(std::uint64_t call_mask) noexcept
    {
        s_seam_virtual_protect_failures = call_mask;
        s_seam_virtual_protect_call = 0;
    }
#endif
} // namespace DetourModKit
