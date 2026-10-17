/**
 * @file hook_retirement.cpp
 * @brief This TU implements the counted thunk decode, the counted drain proof, and HookStack::retire (`[B-106]`).
 */

#include "DetourModKit/hook.hpp"

#include "internal/drain_backoff.hpp"
#include "internal/hook_backend.hpp"
#include "internal/hook_backend_visit.hpp"
#include "internal/hook_fault_boundary.hpp"
#include "internal/lifecycle_context.hpp"
#include "internal/memory_guarded.hpp"
#include "internal/mid_hook_adapter.hpp"

#include "DetourModKit/logger.hpp"

#include "x86_decode.hpp"

#include <windows.h>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

namespace DetourModKit
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    void (*detail::g_counted_drain_probe)(detail::CountedDrainStage) noexcept = nullptr;
#endif

    namespace
    {
        /// The largest thunk the decode copies. An unoptimized thunk with eight stack arguments stays far below it.
        constexpr std::size_t COUNTED_THUNK_MAX_BYTES = 2048;
        /// The incremental-link jumps that the decode follows from a function address to its body.
        constexpr int INCREMENTAL_JUMP_LIMIT = 4;
        /// The calls that one thunk can hold. The detour call and a few unoptimized-build helpers stay below it.
        constexpr std::size_t COUNTED_THUNK_MAX_CALLS = 16;
        /// The return sites that one list holds, and the largest offset from its base.
        constexpr std::size_t RETURN_SITES_PER_LIST = 8;
        constexpr std::uintptr_t RETURN_SITE_MAX_OFFSET = 0xFF;

        /// Follows the jump that an incremental link puts at a function address, so the decode reads the body.
        [[nodiscard]] std::uintptr_t follow_incremental_jumps(std::uintptr_t address) noexcept
        {
            for (int hop = 0; hop < INCREMENTAL_JUMP_LIMIT; ++hop)
            {
                const std::optional<std::uintptr_t> next = DetourModKit::detail::decode_e9_rel32(address);
                if (!next)
                {
                    break;
                }
                address = *next;
            }
            return address;
        }

        /**
         * @brief Packs the returns of the helper calls, given as offsets from @p begin, into return-site lists.
         * @details A stack word equal to a site keeps the drain Busy, so no site address lives in a local here. Each
         *          list keeps its base one byte below its first site, so no base equals a site either.
         * @return False when the sites need more lists than a thunk holds.
         */
        [[nodiscard]] bool pack_helper_sites(
            const std::uint8_t *begin,
            std::span<const std::size_t> site_offsets,
            hook::CountedThunk &thunk
        ) noexcept
        {
            thunk.helper_site_lists = 0;
            std::size_t list_base_offset = 0;
            for (const std::size_t site_offset : site_offsets)
            {
                safetyhook::ReturnSites *list =
                    thunk.helper_site_lists == 0 ? nullptr : &thunk.helper_sites[thunk.helper_site_lists - 1];
                const bool fits = list != nullptr && list->count < RETURN_SITES_PER_LIST &&
                                  site_offset - list_base_offset <= RETURN_SITE_MAX_OFFSET;
                if (!fits)
                {
                    if (thunk.helper_site_lists == thunk.helper_sites.size())
                    {
                        return false;
                    }
                    list = &thunk.helper_sites[thunk.helper_site_lists++];
                    list_base_offset = site_offset - 1;
                    list->code = begin + list_base_offset;
                    list->count = 0;
                }
                list->offsets[list->count++] = static_cast<std::uint8_t>(site_offset - list_base_offset);
            }
            return true;
        }

        /// Runs one idle pass. An unusable pass reads as busy, because the caller then retries or retains.
        [[nodiscard]] bool idle_pass(
            std::span<const safetyhook::AddressRange> ranges,
            std::span<const safetyhook::ReturnSites *const> sites
        ) noexcept
        {
            try
            {
                const std::expected<bool, safetyhook::OsError> idle = safetyhook::threads_idle_outside(ranges, sites);
                return idle.has_value() && *idle;
            }
            catch (...)
            {
                return false;
            }
        }

        /// Sums one counter over every stripe of every block with seq_cst loads (`[B-43]`).
        template <class Member>
        [[nodiscard]] std::uint64_t
        sum_counters(std::span<hook::detail::CountedBlock *const> blocks, Member member) noexcept
        {
            std::uint64_t total = 0;
            for (hook::detail::CountedBlock *const block : blocks)
            {
                for (hook::detail::CountedStripe &stripe : block->stripes)
                {
                    total += std::atomic_ref<std::uint64_t>(stripe.*member).load(std::memory_order_seq_cst);
                }
            }
            return total;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        void note_counted_drain_stage(DetourModKit::detail::CountedDrainStage stage) noexcept
        {
            if (auto *probe = DetourModKit::detail::g_counted_drain_probe)
            {
                probe(stage);
            }
        }
#endif
    } // namespace

    namespace hook
    {
        std::expected<detail::CountedThunkShape, const char *> detail::inspect_counted_thunk(void *entry) noexcept
        {
            const std::uintptr_t begin = follow_incremental_jumps(reinterpret_cast<std::uintptr_t>(entry));
            const std::optional<DetourModKit::detail::FunctionBound> bound = DetourModKit::detail::unwind_bound(begin);
            if (!bound || bound->lo != begin)
            {
                return std::unexpected("no unwind record starts at the thunk");
            }
            const std::size_t size = bound->hi - bound->lo;
            if (size > COUNTED_THUNK_MAX_BYTES)
            {
                return std::unexpected("the thunk is larger than the decode bound");
            }
            std::array<std::uint8_t, COUNTED_THUNK_MAX_BYTES> bytes{};
            if (!DetourModKit::detail::guarded_read_bytes(begin, bytes.data(), size))
            {
                return std::unexpected("the thunk bytes are not readable");
            }
            ZydisDecoder decoder{};
            if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
            {
                return std::unexpected("the decoder did not start");
            }

            // Straight-line code runs in address order, so the first and last locked increments bound the counted
            // window and every call outside them runs uncounted.
            std::array<std::size_t, COUNTED_THUNK_MAX_CALLS> call_starts{};
            std::array<std::size_t, COUNTED_THUNK_MAX_CALLS> call_ends{};
            std::size_t calls = 0;
            std::size_t pushes = 0;
            std::size_t pops = 0;
            std::size_t locks = 0;
            std::size_t first_lock = 0;
            std::size_t last_lock_end = 0;
            bool returned = false;
            std::size_t offset = 0;
            while (offset < size && !returned)
            {
                ZydisDecodedInstruction instruction{};
                if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
                        &decoder,
                        nullptr,
                        bytes.data() + offset,
                        size - offset,
                        &instruction
                    )))
                {
                    return std::unexpected("an instruction of the thunk does not decode");
                }
                const std::size_t end = offset + instruction.length;
                pushes += instruction.mnemonic == ZYDIS_MNEMONIC_PUSH ? 1 : 0;
                pops += instruction.mnemonic == ZYDIS_MNEMONIC_POP ? 1 : 0;
                if ((instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0)
                {
                    first_lock = locks == 0 ? offset : first_lock;
                    last_lock_end = end;
                    ++locks;
                }
                switch (instruction.meta.category)
                {
                case ZYDIS_CATEGORY_CALL:
                    if (calls == call_ends.size())
                    {
                        return std::unexpected("the thunk holds more calls than the decode bound");
                    }
                    call_starts[calls] = offset;
                    call_ends[calls] = end;
                    ++calls;
                    break;
                case ZYDIS_CATEGORY_RET:
                    returned = true;
                    break;
                case ZYDIS_CATEGORY_COND_BR:
                case ZYDIS_CATEGORY_UNCOND_BR:
                case ZYDIS_CATEGORY_INTERRUPT:
                case ZYDIS_CATEGORY_SYSCALL:
                    return std::unexpected("the thunk branches or traps, so its code is not straight-line");
                default:
                    break;
                }
                offset = end;
            }
            if (!returned)
            {
                return std::unexpected("the thunk does not return inside its unwind record");
            }
            if (locks != 2)
            {
                return std::unexpected("the thunk does not hold exactly two locked increments");
            }

            std::array<std::size_t, COUNTED_THUNK_MAX_CALLS> helper_site_offsets{};
            std::size_t helpers = 0;
            std::size_t counted_calls = 0;
            for (std::size_t i = 0; i < calls; ++i)
            {
                if (call_ends[i] <= first_lock || call_starts[i] >= last_lock_end)
                {
                    helper_site_offsets[helpers++] = call_ends[i];
                }
                else
                {
                    ++counted_calls;
                }
            }
            if (counted_calls == 0)
            {
                return std::unexpected("the thunk calls nothing between its counts");
            }

            CountedThunkShape shape{};
            shape.thunk.range = {
                reinterpret_cast<std::uint8_t *>(bound->lo),
                reinterpret_cast<std::uint8_t *>(bound->hi),
            };
            const std::span<const std::size_t> site_offsets{helper_site_offsets.data(), helpers};
            if (!pack_helper_sites(shape.thunk.range.begin, site_offsets, shape.thunk))
            {
                return std::unexpected("the calls outside the counted window need more return sites than a hook holds");
            }
            shape.enter_count_offset = first_lock;
            shape.after_exit_count_offset = last_lock_end;
            shape.helper_calls = helpers;
            shape.counted_calls = counted_calls;
            shape.pushes = pushes;
            shape.pops = pops;
            return shape;
        }

        detail::CountedDrain detail::drain_counted(
            std::span<const safetyhook::AddressRange> ranges,
            std::span<const safetyhook::ReturnSites *const> sites,
            std::span<CountedBlock *const> blocks,
            std::chrono::steady_clock::time_point deadline
        ) noexcept
        {
            DetourModKit::detail::DrainBackoff backoff;
            CountedDrain verdict{};
            for (;;)
            {
                if (idle_pass(ranges, sites))
                {
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_counted_drain_stage(DetourModKit::detail::CountedDrainStage::AfterFirstPass);
#endif
                    // Exits first: equal sums then prove an instant at which no call sat between enter and exit.
                    const std::uint64_t exits = sum_counters(blocks, &CountedStripe::exits);
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_counted_drain_stage(DetourModKit::detail::CountedDrainStage::BetweenCounterReads);
#endif
                    const std::uint64_t enters = sum_counters(blocks, &CountedStripe::enters);
                    verdict.in_flight = enters >= exits ? enters - exits : 0;
#if defined(DMK_ENABLE_TEST_SEAMS)
                    note_counted_drain_stage(DetourModKit::detail::CountedDrainStage::AfterCounterReads);
#endif
                    // Pass 2 finds a thread that still runs the tail after its exit count.
                    if (enters == exits && idle_pass(ranges, sites))
                    {
                        verdict.idle = true;
                        return verdict;
                    }
                }
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    return verdict;
                }
                backoff.pause();
            }
        }

        bool detail::current_thread_returns_into(std::span<const safetyhook::AddressRange> ranges) noexcept
        {
            constexpr DWORD FRAMES_PER_CAPTURE = 62;
            constexpr DWORD FRAME_LIMIT = 1024;
            std::array<void *, FRAMES_PER_CAPTURE> frames{};
            for (DWORD skipped = 0; skipped < FRAME_LIMIT; skipped += FRAMES_PER_CAPTURE)
            {
                const WORD captured = RtlCaptureStackBackTrace(skipped, FRAMES_PER_CAPTURE, frames.data(), nullptr);
                for (WORD i = 0; i < captured; ++i)
                {
                    const auto *const address = static_cast<const std::uint8_t *>(frames[i]);
                    for (const safetyhook::AddressRange &range : ranges)
                    {
                        if (address >= range.begin && address < range.end)
                        {
                            return true;
                        }
                    }
                }
                if (captured < FRAMES_PER_CAPTURE)
                {
                    break;
                }
            }
            return false;
        }

        namespace
        {
            /// The state that one retirement changed on one hook, so a Busy or Refused result can undo it.
            template <class HookImpl> struct RetiringHook
            {
                HookImpl *impl{nullptr};
                bool relay_switched{false};
                bool route_closed{false};
                /// The commit restores this hook, so it adds no residue position.
                bool restores{false};
            };

            /**
             * @brief Puts every relay and route that this retirement changed back as it was.
             * @details A mid route returns to LIVE only for an Active hook that no disable bypassed. Every other mid
             *          route stays CLOSED, because nothing reaches its stub.
             */
            template <class HookImpl> void undo_retirement(std::span<RetiringHook<HookImpl>> hooks) noexcept
            {
                for (RetiringHook<HookImpl> &hook : hooks)
                {
                    if (hook.route_closed)
                    {
                        const bool reopen = hook.impl->status.load(std::memory_order_acquire) == HookState::Active &&
                                            !hook.impl->bypassed;
                        (void)DetourModKit::detail::apply_backend(
                            hook.impl->backend,
                            [reopen](auto &backend) noexcept
                            { reopen ? backend.cancel_route_rundown() : backend.finish_route_rundown(); }
                        );
                        hook.route_closed = false;
                    }
                    if (hook.relay_switched)
                    {
                        (void)DetourModKit::detail::switch_backend(hook.impl->backend, true);
                        hook.relay_switched = false;
                    }
                }
            }

            /// The newest records on one target that the commit prediction reads.
            constexpr std::size_t PREDICTED_RECORDS = 32;

            /// Returns the coordinator key of a hook: the start of its trampoline.
            template <class HookImpl> [[nodiscard]] std::uint8_t *coordinator_key(HookImpl &impl) noexcept
            {
                return DetourModKit::detail::backend_value_or(
                    impl.backend,
                    static_cast<std::uint8_t *>(nullptr),
                    [](const auto &backend) noexcept { return backend.trampoline().data(); }
                );
            }

            /**
             * @brief Marks each hook that the newest-first commit restores.
             * @details The coordinator top restores when the target holds its own patch or the bytes that it saved, so
             *          a disabled top layer restores. A lower hook also restores when every newer record on its target
             *          belongs to a hook that restores first, because each restore puts the next patch back. A newer
             *          layer on an overlapping target with another address reads as no layer here. The budget guard of
             *          ~Hook still pins that case.
             */
            template <class HookImpl>
            void predict_restores(
                std::span<RetiringHook<HookImpl>> hooks,
                const safetyhook::ProcessCoordinator &coordinator
            ) noexcept
            {
                const auto restores = [hooks](const std::uint8_t *key) noexcept
                {
                    return std::ranges::any_of(
                        hooks,
                        [key](const RetiringHook<HookImpl> &hook) noexcept
                        { return hook.restores && coordinator_key(*hook.impl) == key; }
                    );
                };
                bool changed = true;
                while (changed)
                {
                    changed = false;
                    for (RetiringHook<HookImpl> &hook : hooks)
                    {
                        if (hook.restores || DetourModKit::detail::backend_claimed(hook.impl->backend))
                        {
                            continue;
                        }
                        std::uint8_t *const key = coordinator_key(*hook.impl);
                        const DetourModKit::detail::PatchWitness witness =
                            DetourModKit::detail::witness_of(hook.impl->backend);
                        const bool own_bytes = witness == DetourModKit::detail::PatchWitness::OwnedPatch ||
                                               witness == DetourModKit::detail::PatchWitness::Original;
                        if (own_bytes && coordinator.top(key))
                        {
                            hook.restores = changed = true;
                            continue;
                        }
                        std::array<safetyhook::ProcessRouteRecord, PREDICTED_RECORDS> records{};
                        const std::size_t count =
                            coordinator.records_at(reinterpret_cast<std::uint8_t *>(hook.impl->target), records);
                        if (count == 0 || count > records.size())
                        {
                            continue;
                        }
                        // The records arrive newest first. top() skips a retained record that is not enabled.
                        bool newer_restore = true;
                        bool found = false;
                        for (std::size_t i = 0; i < count && !found; ++i)
                        {
                            const safetyhook::ProcessRouteRecord &record = records[i];
                            found = record.trampoline.begin == key;
                            if (!found && (!record.retained || record.enabled) && !restores(record.trampoline.begin))
                            {
                                newer_restore = false;
                                break;
                            }
                        }
                        if (found && newer_restore && records[0].trampoline.begin != key)
                        {
                            hook.restores = changed = true;
                        }
                    }
                }
            }

            /**
             * @brief Measures the time-stamp counter rate while every route is still open.
             * @details A CLOSING spin reads only the counter, because a clock read can be an export that the closing
             *          route hooks. The rate converts the drain deadline into counter ticks before any route closes.
             */
            [[nodiscard]] double counter_ticks_per_nanosecond() noexcept
            {
                const auto first_time = std::chrono::steady_clock::now();
                const std::uint64_t first_ticks = __rdtsc();
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
                const std::uint64_t last_ticks = __rdtsc();
                const auto elapsed =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - first_time)
                        .count();
                if (elapsed <= 0 || last_ticks <= first_ticks)
                {
                    return 1.0;
                }
                return static_cast<double>(last_ticks - first_ticks) / static_cast<double>(elapsed);
            }

            /**
             * @brief Returns the counter ticks left before @p deadline.
             * @details The result never exceeds the closing budget of ~Hook, because callers of a CLOSING route wait at
             *          its gateway for the whole spin.
             */
            [[nodiscard]] std::uint64_t
            remaining_ticks(std::chrono::steady_clock::time_point deadline, double ticks_per_nanosecond) noexcept
            {
                const auto remaining = deadline - std::chrono::steady_clock::now();
                if (remaining <= std::chrono::steady_clock::duration::zero())
                {
                    return 0;
                }
                const double ticks =
                    static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(remaining).count()) *
                    ticks_per_nanosecond;
                const auto budget = static_cast<double>(DetourModKit::detail::CLOSING_DRAIN_TICK_BUDGET);
                return ticks >= budget ? DetourModKit::detail::CLOSING_DRAIN_TICK_BUDGET
                                       : static_cast<std::uint64_t>(ticks);
            }

            /// Builds the result of a retirement that changed nothing and logs why.
            [[nodiscard]] HookRetirement
            unchanged(RetirementOutcome outcome, ErrorCode refusal, std::uint64_t in_flight, const char *why) noexcept
            {
                (void)log().try_log(LogLevel::Info, "hook: HookStack::retire changed nothing: {}.", why);
                return HookRetirement{
                    .outcome = outcome,
                    .in_flight = static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(in_flight, (std::numeric_limits<std::uint32_t>::max)())
                    ),
                    .refusal = refusal,
                };
            }
        } // namespace

        HookRetirement HookStack::retire(std::chrono::milliseconds deadline) noexcept
        {
            if (m_hooks.empty())
            {
                return HookRetirement{};
            }
            if (!DetourModKit::detail::blocking_teardown_permitted())
            {
                return unchanged(
                    RetirementOutcome::Busy,
                    ErrorCode::LoaderLockActive,
                    0,
                    "the caller holds the loader lock or runs in a loader phase"
                );
            }
            const auto now = std::chrono::steady_clock::now();
            const auto headroom = std::chrono::steady_clock::time_point::max() - now;
            const auto stop = deadline <= std::chrono::milliseconds::zero() ? now
                              : deadline >= std::chrono::duration_cast<std::chrono::milliseconds>(headroom)
                                  ? std::chrono::steady_clock::time_point::max()
                                  : now + std::chrono::duration_cast<std::chrono::steady_clock::duration>(deadline);

            using HookImpl = std::remove_pointer_t<decltype(detail::HookAccess::impl(std::declval<const Hook &>()))>;
            std::vector<RetiringHook<HookImpl>> hooks;
            std::vector<safetyhook::AddressRange> ranges;
            std::vector<const safetyhook::ReturnSites *> sites;
            std::vector<detail::CountedBlock *> blocks;
            try
            {
                hooks.reserve(m_hooks.size());
                for (auto it = m_hooks.rbegin(); it != m_hooks.rend(); ++it)
                {
                    HookImpl *const impl = *it ? detail::HookAccess::impl(**it) : nullptr;
                    if (impl == nullptr)
                    {
                        continue;
                    }
                    hooks.push_back(RetiringHook<HookImpl>{.impl = impl});
                    if (impl->counted)
                    {
                        CountedThunk &thunk = *impl->counted;
                        ranges.push_back(thunk.range);
                        if (std::ranges::find(blocks, thunk.block) == blocks.end())
                        {
                            blocks.push_back(thunk.block);
                        }
                        for (std::size_t i = 0; i < thunk.helper_site_lists; ++i)
                        {
                            sites.push_back(&thunk.helper_sites[i]);
                        }
                    }
                }
            }
            catch (...)
            {
                return unchanged(RetirementOutcome::Refused, ErrorCode::OutOfMemory, 0, "the proof storage failed");
            }

            // A counted detour or a mid callback of this stack that retires its own stack waits on itself.
            bool reentrant = detail::current_thread_returns_into(ranges);
            for (const RetiringHook<HookImpl> &hook : hooks)
            {
                if (hook.impl->mid_slot < DetourModKit::detail::MID_ADAPTER_CAPACITY)
                {
                    reentrant = reentrant ||
                                DetourModKit::detail::thread_is_inside_mid_adapter(
                                    DetourModKit::detail::mid_adapter_slots()[hook.impl->mid_slot]
                                ) ||
                                DetourModKit::detail::backend_value_or(
                                    hook.impl->backend,
                                    true,
                                    [](const auto &backend) noexcept { return backend.caller_owns_route(); }
                                );
                }
            }
            if (reentrant)
            {
                return unchanged(
                    RetirementOutcome::Refused,
                    ErrorCode::ReentrantCallRejected,
                    0,
                    "the caller runs inside a counted detour or a mid callback of this stack"
                );
            }
            {
                const safetyhook::ProcessCoordinator coordinator;
                if (!coordinator)
                {
                    return unchanged(
                        RetirementOutcome::Busy,
                        ErrorCode::Ok,
                        0,
                        "the process coordinator is unavailable"
                    );
                }
                predict_restores(std::span<RetiringHook<HookImpl>>{hooks}, coordinator);
                for (const RetiringHook<HookImpl> &hook : hooks)
                {
                    // A claimed hook adds no position, and a restored hook has none to leave.
                    const bool fresh_residue = !hook.restores &&
                                               !DetourModKit::detail::backend_claimed(hook.impl->backend) &&
                                               DetourModKit::detail::witness_of(hook.impl->backend) !=
                                                   DetourModKit::detail::PatchWitness::Original;
                    if (fresh_residue && !DetourModKit::detail::residue_fits_budget(hook.impl->backend))
                    {
                        return unchanged(
                            RetirementOutcome::Refused,
                            ErrorCode::LayerResidueLimitReached,
                            0,
                            "a layer that cannot restore exceeds the residue budget"
                        );
                    }
                }
            }

            // Switch every inline relay off, top layers included. No cell turns Vacant before the commit, so an undo
            // never overwrites a claimed slot.
            for (RetiringHook<HookImpl> &hook : hooks)
            {
                if (!hook.impl->is_inline || DetourModKit::detail::backend_bypassed(hook.impl->backend))
                {
                    continue;
                }
                if (!DetourModKit::detail::switch_backend(hook.impl->backend, false))
                {
                    undo_retirement(std::span<RetiringHook<HookImpl>>{hooks});
                    return unchanged(
                        RetirementOutcome::Refused,
                        ErrorCode::BackendFailed,
                        0,
                        "a relay cannot switch off"
                    );
                }
                hook.relay_switched = true;
            }

            if (!blocks.empty())
            {
                const detail::CountedDrain drained = detail::drain_counted(ranges, sites, blocks, stop);
                if (!drained.idle)
                {
                    undo_retirement(std::span<RetiringHook<HookImpl>>{hooks});
                    return unchanged(
                        RetirementOutcome::Busy,
                        ErrorCode::Ok,
                        drained.in_flight,
                        "a counted call stayed inside its detour past the deadline"
                    );
                }
            }

            // Each mid route drains alone while CLOSING, so a callback of one route can still call through another.
            // The coordinator comes first, because its wait can be an export that the closing route hooks.
            const bool has_mid_route = std::ranges::any_of(
                hooks,
                [](const RetiringHook<HookImpl> &hook) noexcept { return !hook.impl->is_inline; }
            );
            const double ticks_per_nanosecond = has_mid_route ? counter_ticks_per_nanosecond() : 1.0;
            for (RetiringHook<HookImpl> &hook : hooks)
            {
                if (hook.impl->is_inline)
                {
                    continue;
                }
                const std::uint64_t budget = remaining_ticks(stop, ticks_per_nanosecond);
                bool drained = false;
                {
                    const safetyhook::ProcessCoordinator coordinator;
                    (void)DetourModKit::detail::apply_backend(
                        hook.impl->backend,
                        [](auto &backend) noexcept { backend.begin_route_rundown(); }
                    );
                    hook.route_closed = true;
                    drained = DetourModKit::detail::drain_closing_route(hook.impl->backend, budget);
                    (void)DetourModKit::detail::apply_backend(
                        hook.impl->backend,
                        [](auto &backend) noexcept { backend.finish_route_rundown(); }
                    );
                }
                if (!drained)
                {
                    undo_retirement(std::span<RetiringHook<HookImpl>>{hooks});
                    return unchanged(
                        RetirementOutcome::Busy,
                        ErrorCode::Ok,
                        0,
                        "a mid callback stayed inside its route past the deadline"
                    );
                }
            }

            HookRetirement result{};
            while (!m_hooks.empty())
            {
                const std::unique_ptr<Hook> hook = std::move(m_hooks.back());
                m_hooks.pop_back();
                if (!hook)
                {
                    continue;
                }
                switch (detail::HookAccess::teardown(*hook))
                {
                case TeardownOutcome::Restored:
                    ++result.restored;
                    break;
                case TeardownOutcome::Vacated:
                    ++result.vacated;
                    break;
                case TeardownOutcome::Pinned:
                    ++result.pinned;
                    break;
                case TeardownOutcome::Empty:
                    break;
                }
            }
            (void)log().try_log(
                LogLevel::Info,
                "hook: HookStack::retire retired its hooks: {} restored, {} vacated, {} pinned.",
                result.restored,
                result.vacated,
                result.pinned
            );
            return result;
        }
    } // namespace hook

#if defined(DMK_ENABLE_TEST_SEAMS)
    detail::CountedThunkProbe detail::counted_thunk_for_test(const hook::Hook &hook) noexcept
    {
        const auto *const impl = hook::detail::HookAccess::impl(hook);
        if (impl == nullptr || !impl->counted)
        {
            return CountedThunkProbe{};
        }
        const std::expected<hook::detail::CountedThunkShape, const char *> shape =
            hook::detail::inspect_counted_thunk(impl->counted->range.begin);
        if (!shape)
        {
            return CountedThunkProbe{};
        }
        return CountedThunkProbe{
            .entry = shape->thunk.range.begin,
            .range_end = shape->thunk.range.end,
            .enter_count = shape->thunk.range.begin + shape->enter_count_offset,
            .after_exit_count = shape->thunk.range.begin + shape->after_exit_count_offset,
            .helper_calls = shape->helper_calls,
            .counted_calls = shape->counted_calls,
            .pushes = shape->pushes,
            .pops = shape->pops,
        };
    }
#endif
} // namespace DetourModKit
