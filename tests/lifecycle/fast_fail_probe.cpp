// The default nonzero exit rejects a false timeout verdict. The WER control uses a native access violation.

#include <array>
#include <cstdio>
#include <memory>
#include <string>
#include <string_view>

#include <windows.h>

namespace
{
    bool prepare_wer_crash() noexcept
    {
        const UINT process_mode = GetErrorMode();
        const DWORD thread_mode = GetThreadErrorMode();
        std::fprintf(stderr, "WER control error modes: process=0x%X thread=0x%lX\n", process_mode, thread_mode);
        SetErrorMode(process_mode & ~SEM_NOGPFAULTERRORBOX);
        if (!SetThreadErrorMode(thread_mode & ~SEM_NOGPFAULTERRORBOX, nullptr))
            return false;
        return ((GetErrorMode() | GetThreadErrorMode()) & SEM_NOGPFAULTERRORBOX) == 0;
    }

    struct HandleCloser
    {
        void operator()(void *handle) const noexcept { CloseHandle(handle); }
    };
    using UniqueHandle = std::unique_ptr<void, HandleCloser>;

    int run_inherited_error_mode_control()
    {
        std::array<wchar_t, 32768> path{};
        const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0 || length >= path.size())
            return 2;
        std::wstring command = L"\"" + std::wstring{path.data()} + L"\" wer-mode";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process))
            return 2;
        const UniqueHandle child{process.hProcess};
        const UniqueHandle thread{process.hThread};
        if (WaitForSingleObject(child.get(), 10000) != WAIT_OBJECT_0)
        {
            TerminateProcess(child.get(), 2);
            return 2;
        }
        DWORD status = 2;
        return GetExitCodeProcess(child.get(), &status) ? static_cast<int>(status) : 2;
    }
} // namespace

int main(int argc, char *argv[])
{
    if (argc == 2 && std::string_view{argv[1]} == "wer-inherited-mode")
        return run_inherited_error_mode_control();
    if (argc == 2 && std::string_view{argv[1]} == "wer-mode")
    {
        if ((GetErrorMode() & SEM_NOGPFAULTERRORBOX) == 0)
            return 3;
        if (!SetThreadErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS, nullptr))
            return 2;
        return prepare_wer_crash() ? 0 : 4;
    }
    if (argc == 2 && std::string_view{argv[1]} == "wer-crash")
    {
        if (!prepare_wer_crash())
            return 2;
        // The pointer itself is volatile, so neither compiler can prove the store faults and lower it to a trap
        // instruction; the exit status must be STATUS_ACCESS_VIOLATION, not STATUS_ILLEGAL_INSTRUCTION.
        volatile int *volatile target = nullptr;
        *target = 0x2A;
        return 2;
    }

    return argc == 1 ? 1 : 2;
}
