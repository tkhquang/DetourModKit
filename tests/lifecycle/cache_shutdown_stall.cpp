// A stalled admitted reader must not make cache shutdown wait without a bound. A timeout must retain reader-visible
// state ([B-73]). This host stalls one reader inside the shard read path. It checks the deadline, retained shards,
// module reference, and MemoryCache diagnostic. A fresh cycle must release the reference after the reader exits.
// Exit status is the oracle.

#include "DetourModKit/address.hpp"
#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>

namespace DetourModKit::detail
{
    std::uint64_t memory_cache_admitted_reader_count_for_test() noexcept;
    bool memory_cache_has_retained_shards_for_test() noexcept;
    void memory_cache_hold_shared_shard_lock_for_test(Address address, void (*callback)() noexcept) noexcept;
} // namespace DetourModKit::detail

namespace
{
    std::atomic<bool> s_reader_admitted{false};
    std::atomic<bool> s_release_reader{false};

    void stall_admitted_reader() noexcept
    {
        s_reader_admitted.store(true, std::memory_order_release);
        while (!s_release_reader.load(std::memory_order_acquire))
            std::this_thread::yield();
    }

    int fail(const char *what)
    {
        std::fprintf(stderr, "FAIL: %s\n", what);
        return 1;
    }
} // namespace

int main()
{
    using namespace DetourModKit;
    using Clock = std::chrono::steady_clock;

    const std::size_t pins_before = diagnostics::module_pin_count(diagnostics::ModulePinReason::MemoryCache);
    if (!memory::init_cache(32, 5000))
        return fail("init_cache refused a fresh start");

    void *page = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == nullptr)
        return fail("VirtualAlloc probe page");
    if (!memory::is_readable(Region{Address{page}, 1}))
        return fail("warm probe on the running cache");

    // Stall one admitted reader inside the shard read path.
    std::thread reader(
        [page]() { detail::memory_cache_hold_shared_shard_lock_for_test(Address{page}, &stall_admitted_reader); }
    );
    while (!s_reader_admitted.load(std::memory_order_acquire))
        std::this_thread::yield();
    if (detail::memory_cache_admitted_reader_count_for_test() != 1)
    {
        s_release_reader.store(true, std::memory_order_release);
        reader.join();
        return fail("stalled reader is not counted as admitted");
    }

    const std::size_t leaks_before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::MemoryCache);

    // Shutdown must return after its bounded drain expires, retaining instead of freeing.
    const auto t0 = Clock::now();
    memory::shutdown_cache();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0);

    if (elapsed < std::chrono::milliseconds{900})
        return fail("shutdown returned before the drain deadline could expire");
    if (elapsed > std::chrono::seconds{30})
        return fail("shutdown wait was not bounded by the drain deadline");
    if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::MemoryCache) != leaks_before + 1)
        return fail("timeout did not record exactly one MemoryCache retention diagnostic");
    if (diagnostics::module_pin_count(diagnostics::ModulePinReason::MemoryCache) != pins_before + 1)
        return fail("timeout did not retain the precommitted cache module reference");
    if (detail::memory_cache_admitted_reader_count_for_test() != 1)
        return fail("timeout dropped the stalled reader from the admitted count");
    if (!detail::memory_cache_has_retained_shards_for_test())
        return fail("timeout released the shard array while a reader remained admitted");

    // Release the stalled reader. It must exit cleanly through the retained shard array.
    s_release_reader.store(true, std::memory_order_release);
    reader.join();
    if (detail::memory_cache_admitted_reader_count_for_test() != 0)
        return fail("released reader did not leave the admitted count");

    // A later start drains the retained session and reuses the keepalive. Its shutdown releases that reference.
    if (!memory::init_cache(32, 5000))
        return fail("init_cache refused a restart after the reader exited");
    if (!memory::is_readable(Region{Address{page}, 1}))
        return fail("probe on the restarted cache");
    memory::shutdown_cache();
    if (diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::MemoryCache) != leaks_before + 1)
        return fail("clean restart cycle recorded an unexpected retention diagnostic");
    if (diagnostics::module_pin_count(diagnostics::ModulePinReason::MemoryCache) != pins_before)
        return fail("drained restart did not release the cache module reference");

    ::VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}
