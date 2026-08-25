// A VMT seed object can hold slots that name code inside a module whose PE header page is unreadable, while the
// code pages stay executable (packed and protector-guarded images run this way). hook::vmt_for must classify those
// slots from page state (`[B-66]`) and return a typed result. The replaced backend query parsed that header
// unguarded, and this exact geometry terminated the host with an access violation. The exit code is the oracle.

#include "DetourModKit/hook.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <utility>

namespace
{
    int unreadable_header_detour(void *)
    {
        return 0x5EED;
    }
} // namespace

int main()
{
    using namespace DetourModKit;

    HMODULE target_dll = ::LoadLibraryA("hook_target_lib.dll");
    if (target_dll == nullptr)
    {
        std::fprintf(stderr, "FAIL: hook_target_lib.dll did not load, error %lu\n", ::GetLastError());
        return 2;
    }
    auto *target_fn = reinterpret_cast<void *>(::GetProcAddress(target_dll, "compute_damage"));
    if (target_fn == nullptr)
    {
        std::fputs("FAIL: compute_damage export not found\n", stderr);
        return 2;
    }

    // Two header words cover the widest ABI RTTI prefix the capture reads; the trailing zero terminates the walk.
    // Slot 0 is the only callable slot and lives inside the DLL whose header becomes unreadable below.
    std::uintptr_t vtable_storage[4] = {
        0,
        0,
        reinterpret_cast<std::uintptr_t>(target_fn),
        0,
    };
    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(&vtable_storage[2])};
    const std::uintptr_t original_vptr = object.vptr;

    // Protect only the image's first page: the DOS/NT headers become unreadable while compute_damage's code page
    // keeps its execute protection.
    SYSTEM_INFO sys_info{};
    ::GetSystemInfo(&sys_info);
    DWORD previous_protection = 0;
    if (::VirtualProtect(target_dll, sys_info.dwPageSize, PAGE_NOACCESS, &previous_protection) == 0)
    {
        std::fprintf(stderr, "FAIL: header page protection change failed, error %lu\n", ::GetLastError());
        return 2;
    }

    // The claim under proof: this call returns a typed result instead of faulting inside a backend header parse.
    Result<hook::VmtHook> created = hook::vmt_for("VmtUnreadableHeader", &object);

    int exit_code = 0;
    if (!created.has_value())
    {
        std::fprintf(stderr, "FAIL: vmt_for returned %s\n", created.error().message().c_str());
        exit_code = 3;
    }
    else
    {
        std::optional<hook::VmtHook> clone(std::move(*created));
        if (!clone->hook_method(0, &unreadable_header_detour).has_value())
        {
            std::fputs("FAIL: hook_method on the counted slot failed\n", stderr);
            exit_code = 4;
        }
        clone.reset();
        if (object.vptr != original_vptr)
        {
            std::fputs("FAIL: teardown left the seed object on the clone\n", stderr);
            exit_code = 5;
        }
    }

    // Restore the header before teardown so process exit walks a fully readable image.
    DWORD ignored = 0;
    if (::VirtualProtect(target_dll, sys_info.dwPageSize, previous_protection, &ignored) == 0)
    {
        std::fputs("FAIL: header page protection restore failed\n", stderr);
        return 6;
    }
    (void)::FreeLibrary(target_dll);

    if (exit_code == 0)
    {
        std::fputs("OK: vmt_for classified slots from page state under an unreadable module header.\n", stdout);
    }
    std::fflush(stdout);
    std::fflush(stderr);
    return exit_code;
}
