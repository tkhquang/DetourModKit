/**
 * @file veh_survives_unmap.cpp
 * @brief Verifies exception dispatch after a fixture with a MinGW guarded handler unloads.
 * @details The host proves the unmap before a native exception and a C++ throw. MSVC uses SEH and skips this proof.
 */

#include <process.h>
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

namespace
{
    constexpr int EXIT_SKIP = 77;

    int select_teardown(const char *scenario) noexcept
    {
        if (std::strcmp(scenario, "session") == 0)
        {
            return 0;
        }
        if (std::strcmp(scenario, "hook-only") == 0)
        {
            return 1;
        }
        if (std::strcmp(scenario, "with-init-cache") == 0)
        {
            return 2;
        }
        if (std::strcmp(scenario, "hook-outlives-session") == 0)
        {
            return 3;
        }
        if (std::strcmp(scenario, "session-restart") == 0)
            return 4;
        if (std::strcmp(scenario, "cache-restart") == 0)
            return 5;
        return -1;
    }

    // Rejects an unknown token before the toolchain skip, so the WILL_FAIL control holds on both toolchains.
    bool reject_usage(int argc, char **argv) noexcept
    {
        if (argc == 2 && select_teardown(argv[1]) >= 0)
        {
            return false;
        }
        std::fprintf(
            stderr,
            "usage: veh_survives_unmap "
            "<session|hook-only|with-init-cache|hook-outlives-session|session-restart|cache-restart>\n"
        );
        return true;
    }
} // namespace

#if defined(_MSC_VER) || !defined(_WIN64)

int main(int argc, char **argv)
{
    if (reject_usage(argc, argv))
    {
        return 2;
    }
    std::printf("SKIP[%s]: the guarded-read vectored handler exists only on MinGW x64\n", argv[1]);
    return EXIT_SKIP;
}

#else

namespace
{
    constexpr DWORD CONTINUABLE_CODE = 0xE0AB0001;
    constexpr DWORD IDENTITY_FLAGS =
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;

    using RunGenerationFn = int (*)(int, std::uintptr_t, const char *) noexcept;

    // The hook target. The volatile work keeps the prologue long enough for every SafetyHook patch size.
    __attribute__((noinline)) int veh_unmap_target(int amount) noexcept
    {
        volatile int scratch = amount;
        for (int i = 0; i < 4; ++i)
        {
            scratch += i;
            scratch -= i;
        }
        return scratch + 1;
    }

    LONG CALLBACK continue_custom_exception(PEXCEPTION_POINTERS info)
    {
        if (info->ExceptionRecord->ExceptionCode == CONTINUABLE_CODE)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // The two dispatches a stale first-position handler cannot survive. The dispatcher calls it before the host's
    // last-position handler, so a handler in unmapped code faults inside the dispatch and the process dies here.
    void dispatch_exceptions()
    {
        RaiseException(CONTINUABLE_CODE, 0, 0, nullptr);
        try
        {
            throw 42;
        }
        catch (int)
        {
        }
    }
} // namespace

int main(int argc, char **argv)
{
    if (reject_usage(argc, argv))
    {
        return 2;
    }
    const char *const scenario = argv[1];
    const int teardown = select_teardown(scenario);

    if (AddVectoredExceptionHandler(0, continue_custom_exception) == nullptr)
    {
        std::fprintf(stderr, "FAIL[%s]: AddVectoredExceptionHandler refused the last-position handler\n", scenario);
        return 3;
    }
    // Control: both dispatches survive before any generation ran.
    dispatch_exceptions();

    const std::filesystem::path log_path =
        std::filesystem::temp_directory_path() / ("dmk_veh_unmap_" + std::to_string(_getpid()) + "_0.log");
    const std::string log_file = log_path.string();

    const HMODULE image = LoadLibraryW(L"veh_unmap_dll.dll");
    if (image == nullptr)
    {
        std::fprintf(stderr, "FAIL[%s]: LoadLibrary refused veh_unmap_dll.dll (error %lu)\n", scenario, GetLastError());
        return 20;
    }
    const auto run =
        reinterpret_cast<RunGenerationFn>(reinterpret_cast<void *>(GetProcAddress(image, "dmk_veh_run_generation")));
    if (run == nullptr)
    {
        std::fprintf(stderr, "FAIL[%s]: veh_unmap_dll.dll has no dmk_veh_run_generation\n", scenario);
        return 21;
    }
    const void *const probe_address = reinterpret_cast<const void *>(run);

    const int step = run(teardown, reinterpret_cast<std::uintptr_t>(&veh_unmap_target), log_file.c_str());
    if (step != 0)
    {
        std::fprintf(stderr, "FAIL[%s]: the generation failed at step %d\n", scenario, step);
        return 30 + step;
    }

    if (FreeLibrary(image) == 0)
    {
        std::fprintf(stderr, "FAIL[%s]: FreeLibrary failed (error %lu)\n", scenario, GetLastError());
        return 22;
    }
    HMODULE still_mapped = nullptr;
    if (GetModuleHandleExW(IDENTITY_FLAGS, static_cast<LPCWSTR>(probe_address), &still_mapped))
    {
        std::fprintf(stderr, "FAIL[%s]: the image stayed mapped after FreeLibrary\n", scenario);
        return 23;
    }
    int (*volatile restored)(int) noexcept = &veh_unmap_target;
    if (restored(7) != 8)
    {
        std::fprintf(stderr, "FAIL[%s]: the target did not return to its original bytes\n", scenario);
        return 24;
    }

    dispatch_exceptions();

    std::error_code ignored;
    std::filesystem::remove(log_path, ignored);
    std::printf("PASS[%s]: exception dispatch survived the unload\n", scenario);
    return 0;
}

#endif
