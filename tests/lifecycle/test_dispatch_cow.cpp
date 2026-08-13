/**
 * @file test_dispatch_cow.cpp
 * @brief Provides re-entrant EventDispatcher process cases for T-DISPATCH-COW.
 * @details See docs/tests/README.md for the proof contract.
 */

#include "DetourModKit/detail/event_dispatcher.hpp"

#include <cstdio>
#include <string_view>
#include <utility>

namespace
{
    using DetourModKit::EventDispatcher;
    using DetourModKit::Subscription;

    struct CowEvent
    {
        int value{0};
    };

    using Dispatcher = EventDispatcher<CowEvent>;

    /**
     * @brief Re-enters the dispatcher from the target copy constructor.
     * @details The move constructor does not re-enter. A list mutation must copy the installed target to trigger
     *          clear().
     */
    struct ReenterOnCopy
    {
        explicit ReenterOnCopy(Dispatcher *owner) noexcept : dispatcher(owner) {}

        ReenterOnCopy(const ReenterOnCopy &other) noexcept : dispatcher(other.dispatcher)
        {
            if (dispatcher != nullptr)
            {
                dispatcher->clear();
            }
        }
        ReenterOnCopy &operator=(const ReenterOnCopy &) = delete;
        ReenterOnCopy(ReenterOnCopy &&other) noexcept : dispatcher(std::exchange(other.dispatcher, nullptr)) {}
        ReenterOnCopy &operator=(ReenterOnCopy &&) = delete;
        ~ReenterOnCopy() = default;

        void operator()(const CowEvent &) const noexcept {}

        Dispatcher *dispatcher;
    };

    /**
     * @brief Re-enters the dispatcher from the target destructor.
     */
    struct ReenterOnDestroy
    {
        explicit ReenterOnDestroy(Dispatcher *owner) noexcept : dispatcher(owner) {}

        ReenterOnDestroy(const ReenterOnDestroy &other) noexcept : dispatcher(other.dispatcher) {}
        ReenterOnDestroy &operator=(const ReenterOnDestroy &) = delete;
        ReenterOnDestroy(ReenterOnDestroy &&other) noexcept : dispatcher(std::exchange(other.dispatcher, nullptr)) {}
        ReenterOnDestroy &operator=(ReenterOnDestroy &&) = delete;

        ~ReenterOnDestroy() noexcept
        {
            if (dispatcher != nullptr)
            {
                dispatcher->clear();
            }
        }

        void operator()(const CowEvent &) const noexcept {}

        Dispatcher *dispatcher;
    };

    int run_subscribe_copy_reentry()
    {
        Dispatcher dispatcher;
        Subscription first = dispatcher.subscribe(ReenterOnCopy{&dispatcher});
        if (!first.active())
        {
            std::puts("FAIL: the re-entrant-copy handler was not installed");
            return 2;
        }

        Subscription second = dispatcher.subscribe([](const CowEvent &) {});
        if (!second.active())
        {
            std::puts("FAIL: the second subscribe was refused");
            return 3;
        }

        std::puts("SUBSCRIBE_COPIES_NO_CALLABLE_UNDER_LOCK");
        return 0;
    }

    int run_compact_copy_reentry()
    {
        Dispatcher dispatcher;
        Subscription first = dispatcher.subscribe([](const CowEvent &) {});
        Subscription second = dispatcher.subscribe(ReenterOnCopy{&dispatcher});
        if (!first.active() || !second.active())
        {
            std::puts("FAIL: a handler was not installed");
            return 2;
        }

        first.reset();
        if (dispatcher.subscriber_count() != 1)
        {
            std::puts("FAIL: compaction did not reclaim the reset slot");
            return 4;
        }

        std::puts("COMPACT_COPIES_NO_CALLABLE_UNDER_LOCK");
        return 0;
    }

    int run_clear_dtor_reentry()
    {
        Dispatcher dispatcher;
        Subscription sub = dispatcher.subscribe(ReenterOnDestroy{&dispatcher});
        if (!sub.active())
        {
            std::puts("FAIL: the re-entrant-destructor handler was not installed");
            return 2;
        }

        dispatcher.clear();
        if (sub.active())
        {
            std::puts("FAIL: clear did not retire the handler");
            return 5;
        }

        std::puts("CLEAR_DESTROYS_NO_CALLABLE_UNDER_LOCK");
        return 0;
    }

    int run_reset_dtor_reentry()
    {
        Dispatcher dispatcher;
        Subscription sub = dispatcher.subscribe(ReenterOnDestroy{&dispatcher});
        if (!sub.active())
        {
            std::puts("FAIL: the re-entrant-destructor handler was not installed");
            return 2;
        }

        sub.reset();
        if (dispatcher.subscriber_count() != 0)
        {
            std::puts("FAIL: reset did not compact the retired slot");
            return 6;
        }

        std::puts("RESET_DESTROYS_NO_CALLABLE_UNDER_LOCK");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view{argv[1]} == "subscribe-copy-reentry")
    {
        return run_subscribe_copy_reentry();
    }
    if (argc == 2 && std::string_view{argv[1]} == "compact-copy-reentry")
    {
        return run_compact_copy_reentry();
    }
    if (argc == 2 && std::string_view{argv[1]} == "clear-dtor-reentry")
    {
        return run_clear_dtor_reentry();
    }
    if (argc == 2 && std::string_view{argv[1]} == "reset-dtor-reentry")
    {
        return run_reset_dtor_reentry();
    }

    // Reject unknown tokens so CTest cannot report another scenario as a pass.
    std::printf("FAIL: unknown scenario '%s'\n", argc > 1 ? argv[1] : "(none)");
    return 8;
}
