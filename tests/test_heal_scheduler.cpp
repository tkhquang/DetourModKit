#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <windows.h>

#include "DetourModKit/error.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/rtti.hpp"
#include "DetourModKit/rtti_dissect.hpp"

namespace memory = DetourModKit::memory;
namespace rtti = DetourModKit::rtti;
using DetourModKit::Address;
using DetourModKit::ErrorCode;

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern std::uint64_t (*g_rtti_image_generation_override)(std::uintptr_t address) noexcept;
#endif
} // namespace DetourModKit::detail

// These cases pin the HealScheduler's render-loop discipline, frame for frame: a fixed retry interval (NOT a geometric
// backoff), a per-group latch that stops scanning once a group resolves (with no attempt cap while it has not), a
// silent pre-gate that polls a not-yet-live target without spending the retry budget, and a fail-closed heal that keeps
// the nominal offset on a miss and publishes the recovered offset on a hit.

// Scheduling primitives (mock work/gate, no RTTI needed)

TEST(HealSchedulerTest, StartRejectsZeroInterval)
{
    // interval_frames == 0 would make every tick a scan (no rate limit); it is a caller mistake, not a valid cadence.
    const auto sched = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 0});
    ASSERT_FALSE(sched.has_value());
    EXPECT_EQ(sched.error().code, ErrorCode::InvalidArg);
}

TEST(HealSchedulerTest, StartRejectsNegativeDriftThreshold)
{
    const auto scheduler = rtti::HealScheduler::start(rtti::HealConfig{.drift_warn_threshold = -1});
    ASSERT_FALSE(scheduler.has_value());
    EXPECT_EQ(scheduler.error().code, ErrorCode::InvalidArg);
}

TEST(HealSchedulerTest, ScansOnFixedCadenceNotEveryFrame)
{
    // With interval 30 the scan lands on frames 0, 31, 62, ... : the scan frame itself does not decrement, then the
    // next 30 ticks are skips -- a fixed cadence, never a geometric backoff.
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 30});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    int scans = 0;
    sched.add_group(
        [&scans](rtti::HealRun &) noexcept
        {
            ++scans;
            return false; // never resolves, so the group keeps its cadence forever
        });

    sched.tick(); // frame 0 -> scan
    EXPECT_EQ(scans, 1);
    for (int i = 0; i < 30; ++i) // frames 1..30 -> skips
    {
        sched.tick();
    }
    EXPECT_EQ(scans, 1) << "the 30 frames after a scan must all be skips";
    sched.tick(); // frame 31 -> scan
    EXPECT_EQ(scans, 2);
    for (int i = 0; i < 30; ++i) // frames 32..61 -> skips
    {
        sched.tick();
    }
    EXPECT_EQ(scans, 2);
    sched.tick(); // frame 62 -> scan
    EXPECT_EQ(scans, 3);
}

TEST(HealSchedulerTest, LatchStopsScanningAfterSuccess)
{
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 5});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    int scans = 0;
    sched.add_group(
        [&scans](rtti::HealRun &) noexcept
        {
            ++scans;
            return true; // resolves on the first scan
        });

    EXPECT_FALSE(sched.all_resolved());
    sched.tick();
    EXPECT_EQ(scans, 1);
    EXPECT_TRUE(sched.all_resolved());

    // Once latched the group is never scanned again, regardless of how many frames elapse.
    for (int i = 0; i < 200; ++i)
    {
        sched.tick();
    }
    EXPECT_EQ(scans, 1);
}

TEST(HealSchedulerTest, RetriesUntilResolvedWithNoAttemptCap)
{
    // A group that misses keeps retrying on the interval for as long as it takes; there is no attempt cap. Here it
    // resolves only on its FIFTH scan, and every earlier scan must have been attempted.
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    int scans = 0;
    sched.add_group(
        [&scans](rtti::HealRun &) noexcept
        {
            ++scans;
            return scans >= 5;
        });

    // interval 1 -> scans land on ticks 1, 3, 5, 7, 9 (a scan then one skip). Drive well past the fifth scan.
    for (int i = 0; i < 40; ++i)
    {
        sched.tick();
    }
    EXPECT_TRUE(sched.all_resolved());
    EXPECT_EQ(scans, 5) << "must keep retrying to the fifth scan, then latch and stop";
}

TEST(HealSchedulerTest, SilentPreGateDoesNotSpendTheInterval)
{
    // The gate runs BEFORE the interval countdown: while the target is absent the group is polled cheaply every frame
    // and skipped, and crucially the retry budget is NOT consumed -- so the moment the gate opens, the group scans
    // immediately rather than having to wait out an interval.
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 30});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    bool ready = false;
    int scans = 0;
    int gate_calls = 0;
    sched.add_group(
        [&scans](rtti::HealRun &) noexcept
        {
            ++scans;
            return true;
        },
        [&ready, &gate_calls]() noexcept
        {
            ++gate_calls;
            return ready;
        });

    // Target absent for many frames: the gate is polled every frame, but no scan happens and no interval is spent.
    for (int i = 0; i < 100; ++i)
    {
        sched.tick();
    }
    EXPECT_EQ(scans, 0);
    EXPECT_EQ(gate_calls, 100) << "the gate is a cheap per-frame poll";

    // Gate opens: the very next tick scans (the interval budget was never spent during the gated frames).
    ready = true;
    sched.tick();
    EXPECT_EQ(scans, 1);
    EXPECT_TRUE(sched.all_resolved());
}

TEST(HealSchedulerTest, MovedFromSchedulerIsInert)
{
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());

    int scans = 0;
    started->add_group(
        [&scans](rtti::HealRun &) noexcept
        {
            ++scans;
            return true;
        });

    rtti::HealScheduler moved = std::move(*started);

    // The moved-from scheduler is inert: ticking it is a safe no-op, it reports all-resolved vacuously, and config()
    // hands back a default rather than dereferencing the moved-out impl.
    started->tick();
    EXPECT_EQ(scans, 0);
    EXPECT_TRUE(started->all_resolved());
    EXPECT_EQ(started->config().interval_frames, rtti::HealConfig{}.interval_frames);

    // The moved-to scheduler owns the group and drives it.
    moved.tick();
    EXPECT_EQ(scans, 1);
    EXPECT_TRUE(moved.all_resolved());
}

TEST(HealSchedulerTest, AddGroupFromCallbackDefersToNextTick)
{
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    int a = 0;
    int b = 0;
    // Group A registers group B from inside its own work callback. The defer-queue must apply B only after tick's scan
    // loop, so the range-for over the group vector is never invalidated by a reallocation mid-iteration (the UB a naive
    // push_back-during-iteration would cause).
    sched.add_group(
        [&](rtti::HealRun &)
        {
            ++a;
            if (a == 1)
            {
                sched.add_group(
                    [&](rtti::HealRun &) noexcept
                    {
                        ++b;
                        return true;
                    });
            }
            return true; // A latches on its first scan
        });

    sched.tick(); // A scans (deferring B); A latches; B has not run yet
    EXPECT_EQ(a, 1);
    EXPECT_EQ(b, 0);
    EXPECT_FALSE(sched.all_resolved()) << "B is registered but not yet latched";

    sched.tick(); // A is latched (skipped); the deferred B now scans and latches
    EXPECT_EQ(b, 1);
    EXPECT_TRUE(sched.all_resolved());
}

TEST(HealSchedulerTest, ManyGroupsAddedFromCallbackDeferWithoutInvalidatingIteration)
{
    // Hardens the defer contract against the re-entrant dangling-reference hazard: a work callback that registers MANY
    // groups from inside tick's range-for. A naive push_back-during-iteration would reallocate the group vector and
    // dangle the live `Group&` the loop holds (UB); the pending-staging must add every new group only after the scan
    // loop. Registering far more than the initial capacity guarantees a reallocation would have occurred if the
    // deferral were absent, so a clean run (no crash, correct counts) proves the loop reference stayed valid.
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    constexpr int deferred_count = 64;
    std::atomic<int> spawned{0};
    int ran = 0;

    sched.add_group(
        [&](rtti::HealRun &)
        {
            for (int i = 0; i < deferred_count; ++i)
            {
                sched.add_group(
                    [&](rtti::HealRun &) noexcept
                    {
                        ++ran;
                        return true;
                    });
                spawned.fetch_add(1, std::memory_order_relaxed);
            }
            return true; // the seed group latches on its first scan
        });

    sched.tick(); // the seed scans and defers all 64 groups; none has run yet
    EXPECT_EQ(spawned.load(), deferred_count);
    EXPECT_EQ(ran, 0);
    EXPECT_FALSE(sched.all_resolved());

    sched.tick(); // the deferred groups now scan and latch
    EXPECT_EQ(ran, deferred_count);
    EXPECT_TRUE(sched.all_resolved());
}

// heal_into behaviour (with synthetic RTTI)

namespace
{
    // Per-fixture layout offsets shared by every SyntheticVtable instance, mirroring the walker/dissector fixtures: the
    // COL, TypeDescriptor, and vtable storage live well apart from each other and from 4 KiB page boundaries.
    constexpr std::size_t SYN_BUF_SIZE = 4096;
    constexpr std::size_t SYN_COL_OFFSET = 256;
    constexpr std::size_t SYN_TD_OFFSET = SYN_COL_OFFSET + 24; // COL is 24 bytes
    constexpr std::size_t SYN_TD_NAME_OFFSET = SYN_TD_OFFSET + 16;
    constexpr std::size_t SYN_COL_PTR_OFFSET = 2048;
    constexpr std::size_t SYN_VTABLE_OFFSET = SYN_COL_PTR_OFFSET + 8;

    // Static buffer pool for SyntheticVtable storage. Living in the test executable's data segment ensures
    // memory::module_of resolves every synthetic vtable back to the test exe's PE range, which the prelude's
    // bound-check guard requires. The pool is reset between tests.
    constexpr std::size_t SYN_POOL_FIXTURES = 8;
    constexpr std::size_t SYN_POOL_SIZE = SYN_BUF_SIZE * SYN_POOL_FIXTURES;
    alignas(8) std::array<std::byte, SYN_POOL_SIZE> s_syn_pool{};
    std::size_t s_syn_offset = 0;

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::atomic<std::uint64_t> s_heal_image_generation{0};

    std::uint64_t heal_image_generation(std::uintptr_t) noexcept
    {
        return s_heal_image_generation.load(std::memory_order_relaxed);
    }

    class ScopedHealImageGeneration
    {
    public:
        explicit ScopedHealImageGeneration(std::uint64_t generation) noexcept
        {
            s_heal_image_generation.store(generation, std::memory_order_relaxed);
            DetourModKit::detail::g_rtti_image_generation_override = &heal_image_generation;
        }
        ~ScopedHealImageGeneration() noexcept { DetourModKit::detail::g_rtti_image_generation_override = nullptr; }
        ScopedHealImageGeneration(const ScopedHealImageGeneration &) = delete;
        ScopedHealImageGeneration &operator=(const ScopedHealImageGeneration &) = delete;
    };
#endif

    [[nodiscard]] std::byte *syn_alloc() noexcept
    {
        if (s_syn_offset + SYN_BUF_SIZE > s_syn_pool.size())
        {
            return nullptr;
        }
        std::byte *p = s_syn_pool.data() + s_syn_offset;
        s_syn_offset += SYN_BUF_SIZE;
        std::memset(p, 0, SYN_BUF_SIZE);
        return p;
    }

    void syn_reset() noexcept
    {
        s_syn_offset = 0;
    }

    // In-memory MSVC x64 RTTI layout for a type, so heal_into can resolve a real mangled name against the test exe.
    class SyntheticVtable
    {
    public:
        explicit SyntheticVtable(std::string_view mangled_name)
        {
            m_buf = syn_alloc();
            EXPECT_NE(m_buf, nullptr) << "SyntheticVtable pool exhausted; raise SYN_POOL_FIXTURES";
            if (!m_buf)
            {
                return;
            }

            const HMODULE exe = GetModuleHandleW(nullptr);
            EXPECT_NE(exe, nullptr);
            const std::uintptr_t exe_base = reinterpret_cast<std::uintptr_t>(exe);
            const std::uintptr_t buf_base = reinterpret_cast<std::uintptr_t>(m_buf);
            EXPECT_GE(buf_base, exe_base);
            if (buf_base < exe_base)
            {
                return;
            }
            const std::uintptr_t buf_rva = buf_base - exe_base;

            const std::uint32_t signature = 1; // x64 layout with pSelf RVA
            const std::uint32_t col_field = 0;
            const std::uint32_t cd_offset = 0;
            const std::uint32_t td_rva = static_cast<std::uint32_t>(buf_rva + SYN_TD_OFFSET);
            const std::uint32_t class_desc_rva = 0;
            const std::uint32_t self_rva = static_cast<std::uint32_t>(buf_rva + SYN_COL_OFFSET);

            write_at(SYN_COL_OFFSET + 0, signature);
            write_at(SYN_COL_OFFSET + 4, col_field);
            write_at(SYN_COL_OFFSET + 8, cd_offset);
            write_at(SYN_COL_OFFSET + 12, td_rva);
            write_at(SYN_COL_OFFSET + 16, class_desc_rva);
            write_at(SYN_COL_OFFSET + 20, self_rva);

            const std::size_t max_name = SYN_COL_PTR_OFFSET - SYN_TD_NAME_OFFSET - 1;
            const std::size_t name_len = (mangled_name.size() < max_name) ? mangled_name.size() : max_name;
            std::memcpy(m_buf + SYN_TD_NAME_OFFSET, mangled_name.data(), name_len);
            m_buf[SYN_TD_NAME_OFFSET + name_len] = std::byte{0};

            const std::uintptr_t col_addr = buf_base + SYN_COL_OFFSET;
            write_at(SYN_COL_PTR_OFFSET, col_addr);

            m_vtable_addr = buf_base + SYN_VTABLE_OFFSET;
        }

        SyntheticVtable(const SyntheticVtable &) = delete;
        SyntheticVtable &operator=(const SyntheticVtable &) = delete;

        [[nodiscard]] std::uintptr_t vtable() const noexcept { return m_vtable_addr; }

    private:
        template <typename T> void write_at(std::size_t offset, const T &value) noexcept
        {
            static_assert(std::is_trivially_copyable_v<T>);
            std::memcpy(m_buf + offset, &value, sizeof(T));
        }

        std::byte *m_buf = nullptr;
        std::uintptr_t m_vtable_addr = 0;
    };

    // A struct-shaped buffer of pointer-sized fields, plus a helper to place a pointer value at a byte offset. Zeroed,
    // so every unplaced slot resolves to nothing.
    struct SynStruct
    {
        std::array<std::uintptr_t, 96> fields{};

        [[nodiscard]] std::uintptr_t base() const noexcept { return reinterpret_cast<std::uintptr_t>(fields.data()); }

        void put(std::size_t byte_off, std::uintptr_t value) noexcept
        {
            std::memcpy(reinterpret_cast<std::byte *>(base()) + byte_off, &value, sizeof(value));
        }
    };
} // anonymous namespace

class HealSchedulerHealTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        (void)memory::init_cache();
        syn_reset();
    }

    void TearDown() override
    {
        memory::shutdown_cache();
        for (void *p : m_heap_pages)
        {
            VirtualFree(p, 0, MEM_RELEASE);
        }
        m_heap_pages.clear();
    }

    // Allocates a committed page and writes @p vtable_addr as its first qword, so a slot holding this address is a
    // pointer-to-object that identify_pointee_type resolves.
    [[nodiscard]] std::uintptr_t heap_object(std::uintptr_t vtable_addr)
    {
        void *p = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        EXPECT_NE(p, nullptr);
        if (p)
        {
            m_heap_pages.push_back(p);
            std::memcpy(p, &vtable_addr, sizeof(vtable_addr));
        }
        return reinterpret_cast<std::uintptr_t>(p);
    }

private:
    std::vector<void *> m_heap_pages;
};

TEST_F(HealSchedulerHealTest, HealIntoPublishesConfirmedNominalOffset)
{
    SyntheticVtable t(".?AVHealSchedNominal@@");
    SynStruct st;
    constexpr std::ptrdiff_t nominal = 0x80;
    st.put(static_cast<std::size_t>(nominal), heap_object(t.vtable()));

    const rtti::Landmark lm{.nominal_offset = nominal,
                            .expected_mangled = ".?AVHealSchedNominal@@",
                            .indirection = rtti::Indirection::PointerToObject};
    std::atomic<std::ptrdiff_t> slot{nominal};

    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;
    sched.add_group([&](rtti::HealRun &run) noexcept
                    { return run.heal_into("nominal", lm, Address{st.base()}, slot).has_value(); });

    sched.tick();
    EXPECT_TRUE(sched.all_resolved());
    EXPECT_EQ(slot.load(), nominal) << "an undrifted layout confirms at the nominal offset";
}

TEST_F(HealSchedulerHealTest, HealIntoPublishesDriftedOffset)
{
    SyntheticVtable t(".?AVHealSchedDrift@@");
    SynStruct st;
    constexpr std::ptrdiff_t nominal = 0x80;
    constexpr std::ptrdiff_t drift = 0x10;
    // The nominal slot is empty; the field actually lives at nominal + drift after a layout shift.
    st.put(static_cast<std::size_t>(nominal + drift), heap_object(t.vtable()));

    const rtti::Landmark lm{.nominal_offset = nominal,
                            .expected_mangled = ".?AVHealSchedDrift@@",
                            .indirection = rtti::Indirection::PointerToObject};
    std::atomic<std::ptrdiff_t> slot{nominal};

    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;
    sched.add_group([&](rtti::HealRun &run) noexcept
                    { return run.heal_into("drift", lm, Address{st.base()}, slot).has_value(); });

    sched.tick();
    EXPECT_TRUE(sched.all_resolved());
    EXPECT_EQ(slot.load(), nominal + drift) << "the recovered offset must be published to the slot";
}

TEST_F(HealSchedulerHealTest, HealIntoKeepsNominalOnMissThenHealsWhenTargetAppears)
{
    SyntheticVtable t(".?AVHealSchedLate@@");
    SynStruct st; // starts empty: the target is not constructed yet
    constexpr std::ptrdiff_t nominal = 0x80;

    const rtti::Landmark lm{.nominal_offset = nominal,
                            .expected_mangled = ".?AVHealSchedLate@@",
                            .indirection = rtti::Indirection::PointerToObject};
    std::atomic<std::ptrdiff_t> slot{nominal};

    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;
    sched.add_group([&](rtti::HealRun &run) noexcept
                    { return run.heal_into("late", lm, Address{st.base()}, slot, /*required=*/false).has_value(); });

    // First scans miss: the slot is left untouched at its nominal (fail closed, never a guessed offset) and the group
    // stays un-latched so it keeps retrying.
    for (int i = 0; i < 6; ++i)
    {
        sched.tick();
    }
    EXPECT_FALSE(sched.all_resolved());
    EXPECT_EQ(slot.load(), nominal) << "a miss must keep the nominal offset in place";

    // The target is constructed: a later scan heals and latches, with no attempt cap having intervened.
    st.put(static_cast<std::size_t>(nominal), heap_object(t.vtable()));
    for (int i = 0; i < 6; ++i)
    {
        sched.tick();
    }
    EXPECT_TRUE(sched.all_resolved());
    EXPECT_EQ(slot.load(), nominal);
}

// The validity-bearing HealedSlot channel. A required miss must leave the slot Invalid so a slot-only consumer fails
// closed on the retained (readable, dangerous) nominal; an optional miss is Unverified; a resolve is Confirmed and
// authorizes.

TEST_F(HealSchedulerHealTest, RequiredMissPublishesInvalidGeneration)
{
    // Seed the slot's nominal to point at a readable but WRONG-typed object (dangerous: a
    // slot-only consumer would happily dereference it), then heal a REQUIRED landmark for a type absent from the
    // window. The slot must publish Invalid, and every DMK-provided checked accessor must reject it -- a null-only
    // fixture would not prove this, since a dangerous readable value survives.
    SyntheticVtable decoy(".?AVHealDecoyType@@");
    SynStruct st;
    constexpr std::ptrdiff_t nominal = 0x80;
    st.put(static_cast<std::size_t>(nominal), heap_object(decoy.vtable())); // readable + resolvable, but wrong type

    const rtti::Landmark lm{.nominal_offset = nominal,
                            .window = 0x8,                              // tight: no matching type nearby
                            .expected_mangled = ".?AVHealWantedType@@", // absent -> required miss
                            .indirection = rtti::Indirection::PointerToObject};

    rtti::HealedSlot slot;
    slot.seed_nominal(nominal);
    ASSERT_EQ(slot.load().validity, rtti::OffsetValidity::Unverified); // a seeded nominal starts Unverified
    ASSERT_FALSE(slot.authorized().has_value());                       // and is not authorized

    auto started =
        rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1, .escalate = rtti::HealEscalation::Quiet});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;
    bool healed = true;
    sched.add_group(
        [&](rtti::HealRun &run) noexcept
        {
            healed = run.heal_into("wanted", lm, Address{st.base()}, slot, /*required=*/true).has_value();
            return true;
        });
    sched.tick();

    EXPECT_FALSE(healed) << "the required heal must miss";
    const rtti::HealedOffset snap = slot.load();
    EXPECT_EQ(snap.validity, rtti::OffsetValidity::Invalid) << "a required miss publishes Invalid";
    EXPECT_EQ(snap.value, nominal) << "the dangerous nominal is retained (fail closed) but marked unsafe";
    EXPECT_EQ(snap.generation, 0u);
    EXPECT_FALSE(snap.usable());

    const auto authorized = slot.authorized();
    ASSERT_FALSE(authorized.has_value());
    EXPECT_EQ(authorized.error().code, DetourModKit::ErrorCode::OffsetNotConfirmed);
}

TEST_F(HealSchedulerHealTest, OptionalMissPublishesUnverified)
{
    // An OPTIONAL heal that misses publishes Unverified (a best-guess), not Invalid; authorized() still rejects it
    // (only Confirmed authorizes a mutation), but load() reports Unverified so a caller may use it as a hint.
    SynStruct st; // empty: the target is absent
    constexpr std::ptrdiff_t nominal = 0x40;

    const rtti::Landmark lm{.nominal_offset = nominal,
                            .window = 0x8,
                            .expected_mangled = ".?AVHealOptionalAbsent@@",
                            .indirection = rtti::Indirection::PointerToObject};
    rtti::HealedSlot slot;
    slot.seed_nominal(nominal);

    auto started =
        rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1, .escalate = rtti::HealEscalation::Quiet});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;
    sched.add_group(
        [&](rtti::HealRun &run) noexcept
        {
            (void)run.heal_into("optional", lm, Address{st.base()}, slot, /*required=*/false);
            return true;
        });
    sched.tick();

    const rtti::HealedOffset snap = slot.load();
    EXPECT_EQ(snap.validity, rtti::OffsetValidity::Unverified);
    EXPECT_EQ(snap.value, nominal);
    EXPECT_EQ(snap.generation, 0u);
    EXPECT_FALSE(snap.usable());
    EXPECT_FALSE(slot.authorized().has_value()); // Unverified is not Confirmed
}

TEST_F(HealSchedulerHealTest, HealedSlotResolvePublishesConfirmedAndAuthorizes)
{
    // A resolve publishes Confirmed; both checked accessors then return the value, and the generation-checked overload
    // rejects a stale generation (a same-base remap since the heal).
    SyntheticVtable t(".?AVHealConfirmed@@");
    SynStruct st;
    constexpr std::ptrdiff_t nominal = 0x80;
    st.put(static_cast<std::size_t>(nominal), heap_object(t.vtable()));

    const rtti::Landmark lm{.nominal_offset = nominal,
                            .expected_mangled = ".?AVHealConfirmed@@",
                            .indirection = rtti::Indirection::PointerToObject};
    rtti::HealedSlot slot;
    slot.seed_nominal(nominal);

    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;
    sched.add_group(
        [&](rtti::HealRun &run) noexcept
        { return run.heal_into("confirmed", lm, Address{st.base()}, slot, /*required=*/true).has_value(); });
    sched.tick();
    EXPECT_TRUE(sched.all_resolved());

    const rtti::HealedOffset snap = slot.load();
    EXPECT_EQ(snap.validity, rtti::OffsetValidity::Confirmed);
    EXPECT_TRUE(snap.usable());
    EXPECT_EQ(snap.value, nominal);
    const std::uint64_t expected_generation = rtti::image_generation(Address{t.vtable()});
    ASSERT_NE(expected_generation, 0u);
    EXPECT_EQ(snap.generation, expected_generation);

    const auto authorized = slot.authorized();
    ASSERT_TRUE(authorized.has_value());
    EXPECT_EQ(*authorized, nominal);

    EXPECT_TRUE(slot.authorized(snap.generation).has_value());
    EXPECT_FALSE(slot.authorized(0).has_value());
    const std::uint64_t stale_generation = snap.generation == UINT64_MAX ? snap.generation - 1 : snap.generation + 1;
    const auto stale = slot.authorized(stale_generation);
    ASSERT_FALSE(stale.has_value());
    EXPECT_EQ(stale.error().code, DetourModKit::ErrorCode::OffsetNotConfirmed);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST_F(HealSchedulerHealTest, MissingImageGenerationDoesNotLatchConfirmedHeal)
{
    ScopedHealImageGeneration generation(0);
    SyntheticVtable target(".?AVHealNoGeneration@@");
    SynStruct structure;
    constexpr std::ptrdiff_t nominal = 0x80;
    structure.put(static_cast<std::size_t>(nominal), heap_object(target.vtable()));
    const rtti::Landmark landmark{.nominal_offset = nominal,
                                  .expected_mangled = ".?AVHealNoGeneration@@",
                                  .indirection = rtti::Indirection::PointerToObject};
    rtti::HealedSlot slot;
    slot.seed_nominal(nominal);

    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &scheduler = *started;
    scheduler.add_group(
        [&](rtti::HealRun &run) noexcept
        { return run.heal_into("no-generation", landmark, Address{structure.base()}, slot).has_value(); });
    scheduler.tick();

    EXPECT_FALSE(scheduler.all_resolved());
    EXPECT_EQ(slot.load().validity, rtti::OffsetValidity::Invalid);
    EXPECT_FALSE(slot.authorized().has_value());
}
#endif

TEST(HealSchedulerTest, RecursiveTickIsRejectedAndDoesNotInvalidateIteration)
{
    // A recursive tick is rejected, leaving the outer in-flight state active so additions remain deferred.
    auto started = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 1});
    ASSERT_TRUE(started.has_value());
    rtti::HealScheduler &sched = *started;

    std::atomic<int> deferred_ran{0};
    for (int i = 0; i < 4; ++i)
    {
        sched.add_group(
            [&](rtti::HealRun &) noexcept
            {
                sched.tick(); // nested tick: must be rejected, must not clear the outer in-flight state
                // Add many groups: were this to push into `groups` rather than `pending`, the reallocation would
                // invalidate the outer range-for and crash.
                for (int k = 0; k < 32; ++k)
                {
                    sched.add_group(
                        [&](rtti::HealRun &) noexcept
                        {
                            deferred_ran.fetch_add(1, std::memory_order_relaxed);
                            return true;
                        });
                }
                return true; // latch
            });
    }

    sched.tick(); // outer scan must complete without UB
    sched.tick(); // the deferred groups run now
    EXPECT_GT(deferred_ran.load(), 0);
}

TEST(HealedSlotTest, ConcurrentLoadsObserveCoherentSnapshots)
{
    rtti::HealedSlot slot;
    slot.publish(17, 101, rtti::OffsetValidity::Confirmed);

    std::atomic<bool> start{false};
    std::atomic<bool> done{false};
    std::atomic<std::uint32_t> incoherent{0};
    std::thread writer(
        [&]() noexcept
        {
            while (!start.load(std::memory_order_acquire))
            {
            }
            for (std::size_t i = 0; i < 20'000; ++i)
            {
                if ((i & 1U) == 0)
                    slot.publish(17, 101, rtti::OffsetValidity::Confirmed);
                else
                    slot.publish(-29, 202, rtti::OffsetValidity::Invalid);
            }
            done.store(true, std::memory_order_release);
        });

    start.store(true, std::memory_order_release);
    do
    {
        const rtti::HealedOffset snapshot = slot.load();
        const bool first =
            snapshot.value == 17 && snapshot.generation == 101 && snapshot.validity == rtti::OffsetValidity::Confirmed;
        const bool second =
            snapshot.value == -29 && snapshot.generation == 0 && snapshot.validity == rtti::OffsetValidity::Invalid;
        const bool contention_fallback =
            snapshot.value == 0 && snapshot.generation == 0 && snapshot.validity == rtti::OffsetValidity::Invalid;
        if (!first && !second && !contention_fallback)
            incoherent.fetch_add(1, std::memory_order_relaxed);
    } while (!done.load(std::memory_order_acquire));

    writer.join();
    EXPECT_EQ(incoherent.load(std::memory_order_relaxed), 0u);
}

TEST(HealedSlotTest, ConfirmedWithoutGenerationFailsClosed)
{
    rtti::HealedSlot slot;
    slot.publish(42, 0, rtti::OffsetValidity::Confirmed);
    const rtti::HealedOffset snapshot = slot.load();
    EXPECT_EQ(snapshot.validity, rtti::OffsetValidity::Invalid);
    EXPECT_EQ(snapshot.generation, 0u);
    EXPECT_FALSE(snapshot.usable());
    EXPECT_FALSE(slot.authorized().has_value());
    EXPECT_FALSE(slot.authorized(0).has_value());
}
