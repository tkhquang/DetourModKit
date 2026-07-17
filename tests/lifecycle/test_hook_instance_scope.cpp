/**
 * @file test_hook_instance_scope.cpp
 * @brief Proves the per-linked-instance ledger scope hook.hpp documents, using two statically linked kits.
 * @details Loads two DLLs that each link the DetourModKit archive (kit_a, kit_b) and drives both against one address
 *          in a third module. Each scenario runs as its own ctest case, so no scenario inherits another's patches.
 *
 *          The trap this host is built around: src/hook.cpp returns ErrorCode::TargetAlreadyHookedInProcess from TWO
 *          unrelated mechanisms -- the ledger's exact same-kit check, and the foreign-JMP prologue decode that runs
 *          only when the ledger has no record. "kit_b's strict install was refused" would therefore be satisfied by
 *          the decode alone and would pass just as well if both kits shared one ledger, so it proves nothing on its
 *          own.
 *
 *          The discriminator is to leave kit_a's hook UNARMED. Disabled-first creation means an unarmed hook leaves
 *          the prologue pristine, so the decode finds nothing and the ledger becomes the only mechanism that can
 *          refuse. Holding the address, the strict flag, the unarmed state and the code path constant then leaves the
 *          linked instance as the single variable between Refused (same kit, scenario 1) and Installed (two kits,
 *          scenario 2). Scenario 3 arms kit_a to show the strict flag and the cross-instance decode are both live, so
 *          scenario 2 cannot be passing merely because the flag is dead.
 */

#include "DetourModKit/error.hpp"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{
    // Taken from the enum rather than spelled as a literal: the kits return the raw ErrorCode across the C boundary,
    // and a hand-copied value would silently rot the moment an enumerator is inserted above it.
    constexpr int TARGET_ALREADY_HOOKED = static_cast<int>(DetourModKit::ErrorCode::TargetAlreadyHookedInProcess);

    using LedgerAddressFn = std::uintptr_t (*)() noexcept;
    using InstallFn = int (*)(std::uintptr_t, int, int) noexcept;
    using TargetHookedFn = int (*)(std::uintptr_t) noexcept;
    using ReleaseFn = void (*)() noexcept;

    struct Kit
    {
        HMODULE module{nullptr};
        LedgerAddressFn ledger_address{nullptr};
        InstallFn install{nullptr};
        TargetHookedFn target_hooked{nullptr};
        ReleaseFn release{nullptr};
    };

    bool load_kit(const char *name, Kit &kit)
    {
        kit.module = LoadLibraryA(name);
        if (kit.module == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load %s (error %lu)\n", name, GetLastError());
            return false;
        }
        kit.ledger_address = reinterpret_cast<LedgerAddressFn>(
            reinterpret_cast<void *>(GetProcAddress(kit.module, "dmk_kit_ledger_address")));
        kit.install =
            reinterpret_cast<InstallFn>(reinterpret_cast<void *>(GetProcAddress(kit.module, "dmk_kit_install")));
        kit.target_hooked = reinterpret_cast<TargetHookedFn>(
            reinterpret_cast<void *>(GetProcAddress(kit.module, "dmk_kit_target_hooked")));
        kit.release =
            reinterpret_cast<ReleaseFn>(reinterpret_cast<void *>(GetProcAddress(kit.module, "dmk_kit_release")));

        if (kit.ledger_address == nullptr || kit.install == nullptr || kit.target_hooked == nullptr ||
            kit.release == nullptr)
        {
            std::fprintf(stderr, "FAIL: %s is missing an export\n", name);
            return false;
        }
        return true;
    }

    /// Resolves the shared victim address both kits patch. A third module keeps it out of either kit's image.
    bool resolve_target(HMODULE &module, std::uintptr_t &target)
    {
        module = LoadLibraryA("hook_target_lib.dll");
        if (module == nullptr)
        {
            std::fprintf(stderr, "FAIL: could not load hook_target_lib.dll (error %lu)\n", GetLastError());
            return false;
        }
        FARPROC symbol = GetProcAddress(module, "compute_damage");
        if (symbol == nullptr)
        {
            std::fprintf(stderr, "FAIL: hook_target_lib.dll has no compute_damage\n");
            return false;
        }
        target = reinterpret_cast<std::uintptr_t>(reinterpret_cast<void *>(symbol));
        return true;
    }

    struct Fixture
    {
        Fixture() = default;
        Fixture(const Fixture &) = delete;
        Fixture &operator=(const Fixture &) = delete;
        Fixture(Fixture &&) = delete;
        Fixture &operator=(Fixture &&) = delete;

        Kit a;
        Kit b;
        HMODULE target_module{nullptr};
        std::uintptr_t target{0};

        ~Fixture() noexcept
        {
            if (b.release != nullptr)
            {
                b.release();
            }
            if (a.release != nullptr)
            {
                a.release();
            }
            if (b.module != nullptr)
            {
                (void)FreeLibrary(b.module);
            }
            if (a.module != nullptr)
            {
                (void)FreeLibrary(a.module);
            }
            if (target_module != nullptr)
            {
                (void)FreeLibrary(target_module);
            }
        }
    };

    bool setup(Fixture &fixture)
    {
        return load_kit("kit_a.dll", fixture.a) && load_kit("kit_b.dll", fixture.b) &&
               resolve_target(fixture.target_module, fixture.target);
    }

    /**
     * @brief Two separately linked kits must not share one ledger object.
     * @details The structural half of the claim. It cannot stand alone (equal addresses would be a defect, but
     *          different addresses do not by themselves prove the ledgers behave independently), so the behavioral
     *          scenarios carry the contract and this pins the mechanism.
     */
    int run_distinct_ledgers(Fixture &fixture)
    {
        const std::uintptr_t ledger_a = fixture.a.ledger_address();
        const std::uintptr_t ledger_b = fixture.b.ledger_address();

        if (ledger_a == 0 || ledger_b == 0)
        {
            std::fprintf(stderr, "FAIL[distinct]: a kit reported a null ledger address\n");
            return 1;
        }
        if (ledger_a == ledger_b)
        {
            std::fprintf(stderr,
                         "FAIL[distinct]: both kits report ledger %p; two statically linked instances must own two "
                         "ledgers\n",
                         reinterpret_cast<void *>(ledger_a));
            return 1;
        }
        std::printf("PASS[distinct]: kit_a ledger %p, kit_b ledger %p\n", reinterpret_cast<void *>(ledger_a),
                    reinterpret_cast<void *>(ledger_b));
        return 0;
    }

    /**
     * @brief Positive control: within ONE kit the ledger refuses a strict duplicate, with no help from the decode.
     * @details kit_a's first hook stays unarmed, so the target's prologue is pristine and the foreign-JMP decode
     *          cannot be the refuser. A refusal here therefore comes from the ledger alone -- the exact mechanism
     *          scenario 2 requires to be blind across instances. Without this case, scenario 2 would also pass if the
     *          ledger check were simply broken.
     */
    int run_same_kit_refuses(Fixture &fixture)
    {
        const int first = fixture.a.install(fixture.target, 0, 0);
        if (first != 0)
        {
            std::fprintf(stderr, "FAIL[same-kit]: kit_a's unarmed install failed with 0x%04X\n", first);
            return 1;
        }
        if (fixture.a.target_hooked(fixture.target) != 1)
        {
            std::fprintf(stderr, "FAIL[same-kit]: kit_a's ledger does not track the target it just hooked\n");
            return 1;
        }

        const int second = fixture.a.install(fixture.target, 1, 0);
        if (second != TARGET_ALREADY_HOOKED)
        {
            std::fprintf(stderr,
                         "FAIL[same-kit]: kit_a's strict install returned 0x%04X; the ledger must refuse an exact "
                         "same-kit duplicate with TargetAlreadyHookedInProcess (0x%04X)\n",
                         second, TARGET_ALREADY_HOOKED);
            return 1;
        }
        std::printf("PASS[same-kit]: one kit's ledger refused its own duplicate on a pristine prologue\n");
        fixture.a.release();
        return 0;
    }

    /**
     * @brief The differential: the SAME strict install a single kit refuses succeeds across two kits.
     * @details Identical to scenario 1 except that the second install runs through kit_b. Same address, same strict
     *          flag, same unarmed first hook, same code path. kit_b's ledger has no record of kit_a's hook and the
     *          pristine prologue gives the decode nothing, so the install proceeds -- which is exactly the blindness
     *          hook.hpp documents. This is the case that fails if the ledger ever becomes process-shared.
     */
    int run_cross_kit_is_blind(Fixture &fixture)
    {
        const int first = fixture.a.install(fixture.target, 0, 0);
        if (first != 0)
        {
            std::fprintf(stderr, "FAIL[cross-kit]: kit_a's unarmed install failed with 0x%04X\n", first);
            return 1;
        }
        // The decisive witness, and the reason this case cannot pass vacuously: one address, one instant, the same
        // query, opposite answers. A failed install would make kit_a answer 0 and fail here rather than sail through to
        // a strict install that succeeds for the wrong reason; one shared ledger could not answer both ways at all.
        if (fixture.a.target_hooked(fixture.target) != 1)
        {
            std::fprintf(stderr, "FAIL[cross-kit]: kit_a's ledger does not track the target it just hooked\n");
            return 1;
        }
        if (fixture.b.target_hooked(fixture.target) != 0)
        {
            std::fprintf(stderr,
                         "FAIL[cross-kit]: kit_b's ledger already tracks a target only kit_a hooked; the two kits are "
                         "sharing one ledger\n");
            return 1;
        }

        const int second = fixture.b.install(fixture.target, 1, 0);
        if (second != 0)
        {
            std::fprintf(stderr,
                         "FAIL[cross-kit]: kit_b's strict install returned 0x%04X; a separately linked kit's ledger "
                         "must not see kit_a's hook\n",
                         second);
            return 1;
        }
        std::printf("PASS[cross-kit]: the strict install one kit refuses succeeds from a separately linked kit\n");
        fixture.b.release();
        fixture.a.release();
        return 0;
    }

    /**
     * @brief Kills the dead-flag false pass: with kit_a ARMED, kit_b's strict install IS refused.
     * @details Scenario 2 proves the ledger is blind across instances only if the strict flag is live at all. Arming
     *          kit_a plants a real JMP, which kit_b's foreign-prologue decode finds without any ledger record. A
     *          refusal here proves both that fail_if_already_hooked still works from kit_b and that the decode is the
     *          partial cross-instance cover hook.hpp claims it is.
     */
    int run_armed_decode_still_refuses(Fixture &fixture)
    {
        const int first = fixture.a.install(fixture.target, 0, 1);
        if (first != 0)
        {
            std::fprintf(stderr, "FAIL[armed]: kit_a's armed install failed with 0x%04X\n", first);
            return 1;
        }

        const int second = fixture.b.install(fixture.target, 1, 0);
        if (second != TARGET_ALREADY_HOOKED)
        {
            std::fprintf(stderr,
                         "FAIL[armed]: kit_b's strict install returned 0x%04X; the foreign-JMP decode must refuse an "
                         "armed foreign hook with TargetAlreadyHookedInProcess (0x%04X)\n",
                         second, TARGET_ALREADY_HOOKED);
            return 1;
        }
        std::printf("PASS[armed]: the strict flag and the cross-instance prologue decode are both live\n");
        fixture.a.release();
        return 0;
    }
} // namespace

int main(int argc, char **argv)
{
    const char *mode = (argc >= 2) ? argv[1] : "distinct";

    Fixture fixture;
    if (!setup(fixture))
    {
        return 2;
    }

    if (std::strcmp(mode, "distinct") == 0)
    {
        return run_distinct_ledgers(fixture);
    }
    if (std::strcmp(mode, "same-kit") == 0)
    {
        return run_same_kit_refuses(fixture);
    }
    if (std::strcmp(mode, "cross-kit") == 0)
    {
        return run_cross_kit_is_blind(fixture);
    }
    if (std::strcmp(mode, "armed") == 0)
    {
        return run_armed_decode_still_refuses(fixture);
    }

    std::fprintf(stderr, "usage: %s <distinct|same-kit|cross-kit|armed>\n", argv[0]);
    return 2;
}
