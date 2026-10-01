#include "route_copy_protocol.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <span>
#include <string_view>
#include <thread>

namespace
{
    using route_copy::Command;
    using TargetFn = int (*)();
    constexpr DWORD WAIT_MS = 5000;

    struct Participant
    {
        HMODULE module{};
        route_copy::CommandFn command{};

        explicit Participant(const char *path) noexcept : module{LoadLibraryA(path)}
        {
            if (module != nullptr)
            {
                command = reinterpret_cast<route_copy::CommandFn>(
                    reinterpret_cast<void *>(GetProcAddress(module, "route_copy_command"))
                );
            }
        }

        ~Participant() noexcept
        {
            if (module != nullptr)
                FreeLibrary(module);
        }

        Participant(const Participant &) = delete;
        Participant &operator=(const Participant &) = delete;

        std::uintptr_t run(Command operation, void *argument = nullptr) const noexcept
        {
            return command(operation, argument);
        }
    };

    int fail(const char *message) noexcept
    {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return 1;
    }

    bool wait_for(const Participant &participant, Command command, DWORD timeout = WAIT_MS) noexcept
    {
        const auto deadline = GetTickCount64() + timeout;
        while (GetTickCount64() < deadline)
        {
            if (participant.run(command) != 0)
                return true;
            Sleep(1);
        }
        return false;
    }

    bool executable(std::uintptr_t address) noexcept
    {
        MEMORY_BASIC_INFORMATION region{};
        return VirtualQuery(reinterpret_cast<void *>(address), &region, sizeof(region)) == sizeof(region) &&
               region.State == MEM_COMMIT && (region.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
    }

    // Runs the action while the holder participant owns the process coordinator. Returns false without the action
    // when the holder cannot acquire it.
    template <class Action> bool while_held(Participant &holder, Action &&action)
    {
        route_copy::HoldEvents events{
            .entered = CreateEventW(nullptr, TRUE, FALSE, nullptr),
            .release = CreateEventW(nullptr, TRUE, FALSE, nullptr),
        };
        std::thread owner([&holder, &events]() -> void { holder.run(Command::HoldCoordinator, &events); });
        const bool entered = WaitForSingleObject(events.entered, WAIT_MS) == WAIT_OBJECT_0;
        if (entered)
            action();
        SetEvent(events.release);
        owner.join();
        CloseHandle(events.entered);
        CloseHandle(events.release);
        return entered;
    }

    int serialize(Participant &first, Participant &second, bool patch)
    {
        first.run(patch ? Command::HoldPatch : Command::HoldScan);
        second.run(Command::HoldScan);
        std::atomic<std::uintptr_t> first_result{0};
        std::atomic<std::uintptr_t> second_result{0};
        std::thread first_thread(
            [&first, &first_result, patch]() -> void
            { first_result = first.run(patch ? Command::Disable : Command::Scan); }
        );
        if (!wait_for(first, patch ? Command::PatchReached : Command::ScanReached))
        {
            first.run(patch ? Command::ReleasePatch : Command::ReleaseScan);
            first_thread.join();
            return fail("the first transaction did not reach its hold");
        }
        const HANDLE attempted = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        std::thread second_thread(
            [&second, &second_result, attempted]() -> void
            {
                SetEvent(attempted);
                second_result = second.run(Command::Scan);
            }
        );
        const bool started = WaitForSingleObject(attempted, WAIT_MS) == WAIT_OBJECT_0;
        const bool overlapped = wait_for(second, Command::ScanReached, 250);
        first.run(patch ? Command::ReleasePatch : Command::ReleaseScan);
        const bool advanced = wait_for(second, Command::ScanReached);
        second.run(Command::ReleaseScan);
        first_thread.join();
        second_thread.join();
        CloseHandle(attempted);
        if (!started || overlapped || !advanced || first_result == 0 || second_result == 0)
            return fail("independent copies did not serialize their transactions");
        return 0;
    }

    // Fails the process unless destroyed within WAIT_MS. The watch thread waits and terminates through ntdll exports.
    // An open transaction window or a closed route parks each caller of a kernel32 export on the target page.
    class Watchdog
    {
    public:
        explicit Watchdog(const char *failure) : m_failure{failure}
        {
            const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            m_wait =
                reinterpret_cast<NtWaitFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "NtWaitForSingleObject")));
            m_terminate =
                reinterpret_cast<NtTerminateFn>(reinterpret_cast<void *>(GetProcAddress(ntdll, "NtTerminateProcess")));
            m_thread = std::thread([this]() -> void { watch(); });
            WaitForSingleObject(m_started, WAIT_MS);
        }

        ~Watchdog() noexcept
        {
            SetEvent(m_disarmed);
            m_thread.join();
            CloseHandle(m_started);
            CloseHandle(m_disarmed);
        }

        Watchdog(const Watchdog &) = delete;
        Watchdog &operator=(const Watchdog &) = delete;

    private:
        using NtWaitFn = LONG(NTAPI *)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        using NtTerminateFn = LONG(NTAPI *)(HANDLE, LONG);

        void watch() noexcept
        {
            constexpr LONGLONG intervals_per_millisecond = 10'000;
            SetEvent(m_started);
            LARGE_INTEGER timeout{};
            timeout.QuadPart = -static_cast<LONGLONG>(WAIT_MS) * intervals_per_millisecond;
            if (m_wait(m_disarmed, FALSE, &timeout) != static_cast<LONG>(STATUS_TIMEOUT))
                return;
            fail(m_failure);
            std::fflush(stderr);
            m_terminate(m_process, 1);
        }

        const char *m_failure;
        HANDLE m_process{GetCurrentProcess()};
        HANDLE m_started{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        HANDLE m_disarmed{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        NtWaitFn m_wait{};
        NtTerminateFn m_terminate{};
        std::thread m_thread;
    };

    constexpr std::array<const char *, 1> WAIT_EXPORT{"WaitForSingleObject"};
    constexpr std::array<const char *, 6> WAIT_STUB_NEIGHBORS{
        "CreateSemaphoreW",
        "OpenSemaphoreW",
        "ReleaseSemaphore",
        "OpenMutexW",
        "OpenEventW",
        "ResetEvent",
    };
    // MinGW emulated TLS calls these exports on each access.
    constexpr std::array<const char *, 3> TLS_LOOKUP_EXPORTS{
        "GetLastError",
        "SetLastError",
        "TlsGetValue",
    };
    constexpr std::array<const char *, 4> TLS_LOOKUP_NEIGHBORS{
        "GetExitCodeProcess",
        "SortGetHandle",
        "Process32Next",
        "Process32NextW",
    };

    // Hooks the first candidate kernel32 export that shares a page with an anchor export, then tears it down. Each
    // transaction window then covers the anchor code.
    int toggle_on_anchor_page(
        Participant &participant,
        std::span<const char *const> anchors,
        std::span<const char *const> candidates,
        bool call_wait,
        bool fresh_thread
    )
    {
        const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        const auto page_mask = ~static_cast<std::uintptr_t>(system.dwPageSize - 1);
        const auto address_of = [kernel](const char *name) noexcept -> unsigned char *
        { return reinterpret_cast<unsigned char *>(reinterpret_cast<void *>(GetProcAddress(kernel, name))); };
        const auto page_of = [page_mask](const void *address) noexcept -> std::uintptr_t
        { return reinterpret_cast<std::uintptr_t>(address) & page_mask; };
        const char *anchor = nullptr;
        unsigned char *target = nullptr;
        for (const char *anchor_name : anchors)
        {
            for (const char *candidate : candidates)
            {
                if (target == nullptr && address_of(anchor_name) != nullptr && address_of(candidate) != nullptr &&
                    page_of(address_of(candidate)) == page_of(address_of(anchor_name)))
                {
                    anchor = anchor_name;
                    target = address_of(candidate);
                }
            }
        }
        if (target == nullptr)
        {
            std::fprintf(stderr, "SKIP: no listed export shares a page with a listed anchor.\n");
            return 77;
        }
        const auto first_page = page_of(target);
        const auto last_page = page_of(target + 15);
        for (const char *name : {"VirtualProtect", "FlushInstructionCache", "GetCurrentProcess"})
        {
            if (page_of(address_of(name)) == first_page || page_of(address_of(name)) == last_page)
            {
                std::fprintf(stderr, "SKIP: %s shares the target window, so the backend refuses it.\n", name);
                return 77;
            }
        }
        std::fprintf(stderr, "The target shares the page of %s.\n", anchor);
        std::array<unsigned char, 16> original{};
        std::memcpy(original.data(), target, original.size());
        std::uintptr_t leaks = 0;
        {
            const Watchdog watchdog{"a transaction or route parked on the target page"};
            if (participant.run(Command::Install, target) == 0)
                return fail("a hook on the target export did not install");
            if (call_wait)
            {
                using WaitFn = DWORD(WINAPI *)(HANDLE, DWORD);
                WaitFn volatile wait = reinterpret_cast<WaitFn>(reinterpret_cast<void *>(target));
                const HANDLE signaled = CreateEventW(nullptr, TRUE, TRUE, nullptr);
                const auto hits = participant.run(Command::Hits);
                const bool fired =
                    signaled != nullptr && wait(signaled, 0) == WAIT_OBJECT_0 && participant.run(Command::Hits) > hits;
                if (signaled != nullptr)
                    CloseHandle(signaled);
                if (!fired)
                    return fail("the hook on the wait export did not execute");
            }
            if (fresh_thread)
                std::thread([&participant, &leaks]() -> void { leaks = participant.run(Command::Reset); }).join();
            else
                leaks = participant.run(Command::Reset);
        }
        if (leaks != 0 || std::memcmp(original.data(), target, original.size()) != 0)
            return fail("a hook on the target export did not toggle and restore");
        return 0;
    }

    // The transaction window covers the page that holds the coordinator's own wait stub. The page target is an unused
    // export on that page. The export target is the wait stub itself, so its teardown waits through its own route.
    // A fresh teardown thread first touches the participant's emulated TLS during that teardown.
    int toggle_on_wait_stub(Participant &participant, bool hook_wait_export, bool fresh_thread)
    {
        return hook_wait_export
                   ? toggle_on_anchor_page(participant, WAIT_EXPORT, WAIT_EXPORT, true, fresh_thread)
                   : toggle_on_anchor_page(participant, WAIT_EXPORT, WAIT_STUB_NEIGHBORS, false, fresh_thread);
    }

    // The second participant makes its first coordinator connection while the first participant holds it.
    int retry_refused_connection(Participant &first, Participant &second, unsigned char *page)
    {
        TargetFn volatile target = reinterpret_cast<TargetFn>(page);
        // GetTickCount64 advances in whole timer ticks, so the refused two-second wait can read up to one tick short.
        constexpr std::uint64_t REFUSED_WAIT_FLOOR_MS = 2000 - 16;
        const auto identity = first.run(Command::Identity);
        std::uintptr_t refused = 1;
        std::uint64_t elapsed = 0;
        const bool held = while_held(
            first,
            [&second, &refused, &elapsed]() -> void
            {
                const auto start = GetTickCount64();
                refused = second.run(Command::Identity);
                elapsed = GetTickCount64() - start;
            }
        );
        if (identity == 0 || !held || refused != 0 || elapsed < REFUSED_WAIT_FLOOR_MS ||
            second.run(Command::Identity) != identity || second.run(Command::Install, page) == 0 || target() != 37 ||
            second.run(Command::Reset) != 0)
            return fail("a refused first connection disabled the participant");
        return 0;
    }

    // Mirrors the version 1 coordinator header. The live-view control in reject_foreign_view proves each field.
    struct CoordinatorHeader
    {
        std::uint64_t magic;
        std::uint32_t version;
        std::uint32_t bytes;
        void *canonical;
        HANDLE mutex;
        HANDLE mapping;
        std::uint64_t next_order;
    };

    // Maps a whole section for read and write access, or returns null.
    CoordinatorHeader *map_state(HANDLE section) noexcept
    {
        return section == nullptr
                   ? nullptr
                   : static_cast<CoordinatorHeader *>(MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
    }

    // The host creates the coordinator mapping before any participant connects. A wrong magic, version, or size must
    // refuse the connection before the participant trusts its canonical address. A canonical address that is unmapped
    // or that names a view of another section must refuse coordination. A live view of the same section connects.
    int reject_foreign_view(Participant &first)
    {
        constexpr std::uint64_t MAGIC = 0x444d4b524f555445ULL;
        constexpr std::uint32_t STATE_BYTES = 45112;
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
            return fail("the process creation time is unavailable");
        wchar_t lock_name[128]{};
        wchar_t data_name[128]{};
        swprintf_s(
            lock_name,
            L"Local\\DMK.Route.%lu.%08lx%08lx.Lock",
            GetCurrentProcessId(),
            created.dwHighDateTime,
            created.dwLowDateTime
        );
        swprintf_s(
            data_name,
            L"Local\\DMK.Route.%lu.%08lx%08lx.Data",
            GetCurrentProcessId(),
            created.dwHighDateTime,
            created.dwLowDateTime
        );
        const HANDLE lock = CreateMutexW(nullptr, FALSE, lock_name);
        const HANDLE mapping =
            CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, STATE_BYTES, data_name);
        const HANDLE other = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, STATE_BYTES, nullptr);
        auto *const view = map_state(mapping);
        auto *const alias = map_state(mapping);
        auto *const forged = map_state(other);
        void *const released = VirtualAlloc(nullptr, STATE_BYTES, MEM_RESERVE, PAGE_NOACCESS);
        if (lock == nullptr || view == nullptr || alias == nullptr || forged == nullptr || released == nullptr ||
            !VirtualFree(released, 0, MEM_RELEASE))
            return fail("the host did not create the coordinator mapping");
        // Each header names a view of the coordinator section, so only its magic, version, or size refuses it. A
        // participant that kept that view fails the later checks.
        const std::array<CoordinatorHeader, 3> incompatible{{
            {MAGIC ^ 1, 1, STATE_BYTES, alias, lock, mapping, 1},
            {MAGIC, 2, STATE_BYTES, alias, lock, mapping, 1},
            {MAGIC, 1, STATE_BYTES + 8, alias, lock, mapping, 1},
        }};
        std::uintptr_t accepted = 0;
        for (const CoordinatorHeader &header : incompatible)
        {
            *view = header;
            accepted |= first.run(Command::Identity);
        }
        *view = CoordinatorHeader{MAGIC, 1, STATE_BYTES, released, lock, mapping, 1};
        *forged = *view;
        const auto unmapped = first.run(Command::Identity);
        view->canonical = forged;
        const auto foreign = first.run(Command::Identity);
        view->canonical = view;
        const auto identity = first.run(Command::Identity);
        if (accepted != 0 || unmapped != 0 || foreign != 0 || identity != reinterpret_cast<std::uintptr_t>(view) ||
            first.run(Command::Records) != 0)
            return fail("a participant trusted an incompatible header or a canonical address outside the section");
        return 0;
    }

    // An older toggle under a live newer participant writes nothing and reports LayerConflict.
    int report_layer_conflict(
        Participant &first,
        Participant &second,
        unsigned char *page,
        const std::array<unsigned char, 11> &code
    )
    {
        TargetFn volatile target = reinterpret_cast<TargetFn>(page);
        // Both layers are disarmed, so only the coordinator layer order refuses the older arm.
        if (first.run(Command::Install, page) == 0 || first.run(Command::Disable) == 0 ||
            second.run(Command::Install, page) == 0 || second.run(Command::Disable) == 0 ||
            first.run(Command::EnableLayerConflict) == 0 || std::memcmp(page, code.data(), code.size()) != 0 ||
            target() != 37 || second.run(Command::Reset) != 0)
            return fail("an older participant arm did not report LayerConflict");
        // The disarmed newer layer saved the older patch as its prologue, so an older restore erases that patch.
        if (first.run(Command::Enable) == 0)
            return fail("the older participant did not arm after the newer layer retired");
        std::array<unsigned char, 16> armed{};
        std::memcpy(armed.data(), page, armed.size());
        if (second.run(Command::Install, page) == 0 || second.run(Command::Disable) == 0 ||
            std::memcmp(page, armed.data(), armed.size()) != 0 || first.run(Command::DisableLayerConflict) == 0 ||
            std::memcmp(page, armed.data(), armed.size()) != 0 || second.run(Command::Reset) != 0 ||
            first.run(Command::Disable) == 0 || std::memcmp(page, code.data(), code.size()) != 0 ||
            first.run(Command::Reset) != 0)
            return fail("an older participant restore did not report LayerConflict");
        return 0;
    }

    int reconcile_stale_state_before_layer_conflict(
        Participant &first,
        Participant &second,
        unsigned char *page,
        const std::array<unsigned char, 11> &code
    )
    {
        TargetFn volatile target = reinterpret_cast<TargetFn>(page);
        // A foreign restore leaves the older hook Active over Original bytes. Its arm reconciles that state to
        // Disabled before the coordinator refuses it under the newer layer.
        if (first.run(Command::Install, page) == 0 || first.run(Command::Enabled) == 0)
            return fail("the older participant did not arm");
        std::memcpy(page, code.data(), code.size());
        FlushInstructionCache(GetCurrentProcess(), page, code.size());
        if (second.run(Command::Install, page) == 0 || second.run(Command::Disable) == 0 ||
            std::memcmp(page, code.data(), code.size()) != 0)
            return fail("the newer participant did not save and restore the original prologue");
        if (first.run(Command::EnableLayerConflict) == 0 || first.run(Command::Enabled) != 0 ||
            std::memcmp(page, code.data(), code.size()) != 0 || target() != 37 || first.run(Command::Hits) != 0)
            return fail("the refused arm did not publish the reconciled Disabled state");
        if (second.run(Command::Reset) != 0 || first.run(Command::Enable) == 0 || target() != 37 ||
            first.run(Command::Hits) != 1 || first.run(Command::Reset) != 0 ||
            std::memcmp(page, code.data(), code.size()) != 0)
            return fail("the reconciled older hook did not arm after the newer layer retired");
        return 0;
    }

    // A held coordinator refuses an arm, a disarm, and the teardown restore of an armed hook. Each warning names the
    // cause.
    int report_coordinator_refusal(Participant &first, Participant &second, unsigned char *page)
    {
        TargetFn volatile target = reinterpret_cast<TargetFn>(page);
        if (first.run(Command::Install, page) == 0 || target() != 37 || first.run(Command::Disable) == 0)
            return fail("the first hook did not execute and disarm");
        std::uintptr_t armed = 1;
        std::uintptr_t disarmed = 1;
        std::uintptr_t leaks = 0;
        if (!while_held(second, [&first, &armed]() -> void { armed = first.run(Command::Enable); }) ||
            first.run(Command::Enable) == 0 ||
            !while_held(
                second,
                [&first, &disarmed, &leaks]() -> void
                {
                    disarmed = first.run(Command::Disable);
                    leaks = first.run(Command::Reset);
                }
            ) ||
            armed != 0 || disarmed != 0 || leaks != 1 || first.run(Command::Warnings) != 3 || target() != 37)
            return fail("a coordinator refusal of a toggle or teardown restore was not reported");
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view scenario{argv[1]};
    if (scenario != "scans" && scenario != "patch" && scenario != "layers" && scenario != "unload" &&
        scenario != "layers-inline" && scenario != "missing" && scenario != "incompatible" && scenario != "capacity" &&
        scenario != "timeout" && scenario != "stub-page" && scenario != "layers-overlap" && scenario != "drain-leak" &&
        scenario != "adapter-leak" && scenario != "wait-export" && scenario != "stub-thread" &&
        scenario != "connect-retry" && scenario != "layer-conflict" && scenario != "stale-layer-conflict" &&
        scenario != "refusal-cause" && scenario != "foreign-view" && scenario != "timeout-armed" &&
        scenario != "teardown-retry" && scenario != "teardown-retry-armed" && scenario != "tls-page")
        return 2;
    Participant first{"route_copy_a.dll"};
    Participant second{"route_copy_b.dll"};
    if (first.command == nullptr || second.command == nullptr || first.command == second.command)
        return fail("two independently linked participants are required");
    // Retained routes require this target until process exit.
    auto *page =
        static_cast<unsigned char *>(VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (page == nullptr)
        return fail("target allocation failed");
    const std::array<unsigned char, 11> code{0x90, 0x90, 0x90, 0x90, 0x90, 0xB8, 37, 0, 0, 0, 0xC3};
    std::memcpy(page, code.data(), code.size());
    FlushInstructionCache(GetCurrentProcess(), page, code.size());
    TargetFn volatile target = reinterpret_cast<TargetFn>(page);
    if (scenario == "connect-retry")
        return retry_refused_connection(first, second, page);
    if (scenario == "foreign-view")
        return reject_foreign_view(first);
    const auto identity = first.run(Command::Identity);
    if (identity == 0 || identity != second.run(Command::Identity))
        return fail("participants did not share the same data owner");
    if (scenario == "layer-conflict")
        return report_layer_conflict(first, second, page, code);
    if (scenario == "stale-layer-conflict")
        return reconcile_stale_state_before_layer_conflict(first, second, page, code);
    if (scenario == "refusal-cause")
        return report_coordinator_refusal(first, second, page);
    if (scenario == "scans")
        return serialize(first, second, false);
    if (scenario == "stub-page" || scenario == "wait-export" || scenario == "stub-thread")
        return toggle_on_wait_stub(first, scenario == "wait-export", scenario == "stub-thread");
    if (scenario == "tls-page")
        return toggle_on_anchor_page(first, TLS_LOOKUP_EXPORTS, TLS_LOOKUP_NEIGHBORS, false, false);
    if (scenario == "capacity")
    {
        if (first.run(Command::Fill) != 512 || second.run(Command::Install, page) != 0)
            return fail("the process registration bound did not refuse another participant");
        first.run(Command::Clear);
        if (second.run(Command::Records) != 0 || second.run(Command::Install, page) == 0 || target() != 37 ||
            second.run(Command::Reset) != 0 || first.run(Command::Records) != 0)
            return fail("a refused registration left stale state");
        return 0;
    }
    const auto install = scenario == "layers-inline" ? Command::InstallInline : Command::Install;
    // The newer entry patch relocates the older jump from inside its own window.
    const std::size_t older_offset = scenario == "layers-overlap" ? 2 : 0;
    if (first.run(install, page + older_offset) == 0 || target() != 37 || first.run(Command::Hits) != 1)
        return fail("the first hook did not execute");
    if (scenario == "missing" || scenario == "incompatible")
    {
        const auto trampoline = first.run(Command::Trampoline);
        if (first.run(Command::Disable) == 0)
            return fail("the route did not close before the refusal");
        first.run(scenario == "missing" ? Command::Unavailable : Command::Incompatible);
        const auto retained = first.run(Command::Reset);
        first.run(Command::RestoreCoordination);
        if (retained != 1 || first.run(Command::Warnings) != 1 || !executable(trampoline) || target() != 37 ||
            second.run(Command::Records) != 1)
            return fail("uncoordinated reclamation released a reachable record");
        return 0;
    }
    if (scenario == "teardown-retry" || scenario == "teardown-retry-armed")
    {
        const auto trampoline = first.run(Command::Trampoline);
        if (scenario == "teardown-retry" && first.run(Command::Disable) == 0)
            return fail("the route did not disarm before the transient refusal");
        first.run(Command::RefuseNextAcquisition);
        if (first.run(Command::Reset) != 0 || first.run(Command::Warnings) != 0 || second.run(Command::Records) != 0 ||
            executable(trampoline) || std::memcmp(page, code.data(), code.size()) != 0 || target() != 37)
            return fail("a transient coordinator refusal prevented clean teardown");
        return 0;
    }
    if (scenario == "timeout" || scenario == "timeout-armed")
    {
        const bool armed = scenario == "timeout-armed";
        const auto trampoline = first.run(Command::Trampoline);
        if (!armed && first.run(Command::Disable) == 0)
            return fail("the route did not close before contention");
        std::uintptr_t retained = 0;
        std::uint64_t elapsed = 0;
        const bool entered = while_held(
            second,
            [&first, &retained, &elapsed]() -> void
            {
                const auto start = GetTickCount64();
                retained = first.run(Command::Reset);
                elapsed = GetTickCount64() - start;
            }
        );
        const auto records = second.run(Command::Records);
        std::printf(
            "coordinator teardown: armed=%u elapsed_ms=%llu leaks=%llu records=%llu\n",
            armed ? 1U : 0U,
            static_cast<unsigned long long>(elapsed),
            static_cast<unsigned long long>(retained),
            static_cast<unsigned long long>(records)
        );
        if (!entered || elapsed < 2000 || elapsed > 12000 || retained != 1 || first.run(Command::Warnings) != 1 ||
            records != 1 || !executable(trampoline) || target() != 37 || first.run(Command::Hits) != 1 ||
            (std::memcmp(page, code.data(), code.size()) != 0) != armed)
            return fail("a coordinator timeout did not retain and report the route");
        return 0;
    }
    if (scenario == "patch")
        return serialize(first, second, true);
    if (scenario == "unload")
    {
        if (first.run(Command::Reset) != 0)
            return fail("clean participant retained its hook");
        const auto address = reinterpret_cast<const wchar_t *>(first.command);
        FreeLibrary(first.module);
        first.module = nullptr;
        HMODULE owner{};
        if (GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                address,
                &owner
            ))
            return fail("the first participant did not unmap");
        try
        {
            throw 37;
        }
        catch (int value)
        {
            if (value != 37)
                return 1;
        }
        if (second.run(Command::Identity) != identity || second.run(Command::Records) != 0 ||
            second.run(Command::Install, page) == 0 || target() != 37 || second.run(Command::Reset) != 0 ||
            second.run(Command::Records) != 0)
            return fail("the coordinator failed after participant unload");
        return 0;
    }
    const auto older = first.run(Command::Trampoline);
    if (second.run(Command::Install, page) == 0 || target() != 37 || second.run(Command::Hits) != 1)
        return fail("the newer hook did not execute");
    if (first.run(Command::Disable) != 0)
        return fail("an older participant changed the newer layer");
    if (scenario == "drain-leak")
    {
        second.run(Command::SelfReset);
        if (target() != 37 || second.run(Command::Hits) != 2 || first.run(Command::Disable) == 0 ||
            std::memcmp(page, code.data(), code.size()) != 0 || first.run(Command::Reset) != 1 || !executable(older))
            return fail("a leaked newer route blocked the older layer or lost its dependency");
        return 0;
    }
    if (scenario == "adapter-leak")
    {
        // The newer teardown restores the target and then leaks at its bounded adapter drain.
        const bool leaked = second.run(Command::HoldAdapter) != 0 && second.run(Command::Reset) == 1;
        const bool released = first.run(Command::Disable) != 0 && std::memcmp(page, code.data(), code.size()) == 0;
        const bool retained = first.run(Command::Reset) == 1 && executable(older);
        second.run(Command::ReleaseAdapter);
        if (!leaked || !released || !retained)
            return fail("an adapter drain failure blocked the older layer or lost its dependency");
        return 0;
    }
    second.run(Command::HoldEntry);
    std::atomic<int> observed{0};
    std::thread caller([&target, &observed]() -> void { observed = target(); });
    if (!wait_for(second, Command::EntryReached))
    {
        second.run(Command::ReleaseEntry);
        caller.join();
        return fail("the newer gateway did not park");
    }
    const auto newer_retention = second.run(Command::Reset);
    const auto older_retention = first.run(Command::Reset);
    const bool retained = executable(older);
    // The parked caller also fails the idle scan, so only the reason proves the newer-record refusal.
    const bool dependent = first.run(Command::DependentRetentions) == 1;
    // Only a retained mark on the newer record lets the older layer restore its target.
    const bool restored = std::memcmp(page, code.data(), code.size()) == 0;
    const auto first_address = reinterpret_cast<const wchar_t *>(first.command);
    const auto second_address = reinterpret_cast<const wchar_t *>(second.command);
    FreeLibrary(first.module);
    FreeLibrary(second.module);
    first.module = nullptr;
    second.module = nullptr;
    HMODULE owner{};
    constexpr DWORD lookup_flags =
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    if (!GetModuleHandleExW(lookup_flags, first_address, &owner) ||
        !GetModuleHandleExW(lookup_flags, second_address, &owner))
    {
        (void)fail("a retained route lost its code provider");
        ExitProcess(1);
    }
    second.run(Command::ReleaseEntry);
    caller.join();
    if (newer_retention != 1 || older_retention != 1 || !retained || !dependent || !restored || observed != 37)
        return fail("the newer route lost its older dependency");
    return 0;
}
