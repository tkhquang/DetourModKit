#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
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

// These cases pin the HealScheduler's render-loop discipline, frame for frame: a fixed retry interval (NOT a geometric
// backoff), a per-group latch that stops scanning once a group resolves (with no attempt cap while it has not), a
// silent pre-gate that polls a not-yet-live target without spending the retry budget, and a fail-closed heal that keeps
// the nominal offset on a miss and publishes the recovered offset on a hit.

// --- Scheduling primitives (mock work/gate, no RTTI needed) ------------------------------------------------------

TEST(HealSchedulerTest, StartRejectsZeroInterval)
{
    // interval_frames == 0 would make every tick a scan (no rate limit); it is a caller mistake, not a valid cadence.
    const auto sched = rtti::HealScheduler::start(rtti::HealConfig{.interval_frames = 0});
    ASSERT_FALSE(sched.has_value());
    EXPECT_EQ(sched.error().code, ErrorCode::InvalidArg);
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

// --- heal_into behaviour (with synthetic RTTI) -------------------------------------------------------------------

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
