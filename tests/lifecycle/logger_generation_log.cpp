/**
 * @file logger_generation_log.cpp
 * @brief Proves the ModInfo::log_open_mode contract across real process generations.
 * @details A staged-generation reload creates a fresh process-default logger per generation. The first child uses
 *          Session::start. The second child uses bootstrap. Both children share one log file and complete Session
 *          teardown. The append case requires the second file to start with the first file's exact bytes. The
 *          default case requires the second open to erase them.
 */

#include "DetourModKit/logger.hpp"
#include "DetourModKit/session.hpp"

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <process.h>
#include <string>
#include <string_view>

#include <windows.h>

namespace
{
    constexpr std::string_view GEN1_MARKER = "DMK_GENLOG_MARKER_GEN1";
    constexpr std::string_view GEN2_MARKER = "DMK_GENLOG_MARKER_GEN2";
    constexpr std::string_view SEED_MARKER = "DMK_GENLOG_SEED_PREFIX\n";

    std::filesystem::path shared_log_path()
    {
        static std::atomic<unsigned int> s_path_counter{0};
        const unsigned int counter = s_path_counter.fetch_add(1, std::memory_order_relaxed);
        return std::filesystem::temp_directory_path() /
               ("dmk_logger_generation_" + std::to_string(static_cast<unsigned long>(_getpid())) + "_" +
                std::to_string(counter) + ".log");
    }

    std::wstring own_executable_path()
    {
        wchar_t buffer[MAX_PATH]{};
        const DWORD length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
        if (length == 0 || length >= MAX_PATH)
        {
            return {};
        }
        return std::wstring(buffer, length);
    }

    std::string read_file_bytes(const std::filesystem::path &path)
    {
        // Binary mode makes the prefix comparison cover each record and each line terminator.
        std::ifstream stream(path, std::ios::binary);
        if (!stream.is_open())
        {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    }

    int run_generation(std::wstring_view route_token, std::wstring_view mode_token, std::wstring_view marker,
                       const std::filesystem::path &log_path)
    {
        const std::wstring exe = own_executable_path();
        if (exe.empty())
        {
            std::fprintf(stderr, "GetModuleFileNameW failed\n");
            return 20;
        }

        std::wstring command_line = L"\"" + exe + L"\" child " + std::wstring(route_token) + L" " +
                                    std::wstring(mode_token) + L" " + std::wstring(marker) + L" \"" +
                                    log_path.wstring() + L"\"";

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(exe.c_str(), command_line.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup,
                            &process))
        {
            std::fprintf(stderr, "CreateProcessW failed: %lu\n", GetLastError());
            return 21;
        }
        CloseHandle(process.hThread);

        // CTest owns the hang verdict. This local wait limits the delay before the child-timeout diagnostic.
        const DWORD wait = WaitForSingleObject(process.hProcess, 45000);
        if (wait != WAIT_OBJECT_0)
        {
            TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hProcess);
            std::fprintf(stderr, "child generation did not exit (wait=%lu)\n", wait);
            return 22;
        }

        DWORD exit_code = 1;
        GetExitCodeProcess(process.hProcess, &exit_code);
        CloseHandle(process.hProcess);
        if (exit_code != 0)
        {
            std::fprintf(stderr, "child generation failed with exit code %lu\n", exit_code);
        }
        return static_cast<int>(exit_code);
    }

    int run_child(std::string_view route_token, std::string_view mode_token, std::string_view marker,
                  std::string_view log_path)
    {
        DetourModKit::ModInfo info{};
        info.name = "DMKGenLogProof";
        info.log_file = log_path;
        if (mode_token == "append")
        {
            info.log_open_mode = DetourModKit::LogOpenMode::Append;
        }
        else if (mode_token != "truncate")
        {
            std::fprintf(stderr, "unknown child mode token\n");
            return 12;
        }

        if (route_token == "session")
        {
            auto session = DetourModKit::Session::start(info);
            if (!session)
            {
                std::fprintf(stderr, "Session::start failed: %s\n", session.error().message().c_str());
                return 10;
            }
            if (!DetourModKit::log().log(DetourModKit::LogLevel::Info, marker))
            {
                std::fprintf(stderr, "marker record was not accepted\n");
                return 11;
            }
            return 0;
        }
        if (route_token != "bootstrap")
        {
            std::fprintf(stderr, "unknown child route token\n");
            return 13;
        }

        DetourModKit::Result<void> started =
            DetourModKit::bootstrap(info,
                                    [marker](DetourModKit::Session &) -> DetourModKit::Result<void>
                                    {
                                        (void)DetourModKit::log().log(DetourModKit::LogLevel::Info, marker);
                                        return {};
                                    });
        if (!started)
        {
            std::fprintf(stderr, "bootstrap failed: %s\n", started.error().message().c_str());
            return 14;
        }
        DetourModKit::Result<void> drained = DetourModKit::shutdown_and_wait();
        if (!drained)
        {
            std::fprintf(stderr, "bootstrap drain failed: %s\n", drained.error().message().c_str());
            return 15;
        }
        return 0;
    }

    int run_scenario(bool append_mode)
    {
        const std::filesystem::path log_path = shared_log_path();
        std::error_code cleanup_error;
        std::filesystem::remove(log_path, cleanup_error);

        struct FileCleanup
        {
            const std::filesystem::path &path;
            ~FileCleanup() noexcept
            {
                std::error_code error;
                std::filesystem::remove(path, error);
            }
        } const file_cleanup{log_path};

        const std::wstring mode_token = append_mode ? L"append" : L"truncate";

        if (append_mode)
        {
            std::ofstream seed_stream(log_path, std::ios::binary | std::ios::trunc);
            seed_stream.write(SEED_MARKER.data(), static_cast<std::streamsize>(SEED_MARKER.size()));
            seed_stream.close();
            if (!seed_stream)
            {
                std::fprintf(stderr, "seed prefix write failed\n");
                return 29;
            }
        }

        if (const int gen1 = run_generation(L"session", mode_token, L"DMK_GENLOG_MARKER_GEN1", log_path); gen1 != 0)
        {
            return gen1;
        }
        const std::string first_bytes = read_file_bytes(log_path);
        if (first_bytes.empty() || first_bytes.find(GEN1_MARKER) == std::string::npos)
        {
            std::fprintf(stderr, "generation 1 marker missing from its own log\n");
            return 30;
        }
        if (append_mode && !first_bytes.starts_with(SEED_MARKER))
        {
            std::fprintf(stderr, "Session::start append mode did not preserve the seed prefix\n");
            return 34;
        }

        if (const int gen2 = run_generation(L"bootstrap", mode_token, L"DMK_GENLOG_MARKER_GEN2", log_path); gen2 != 0)
        {
            return gen2;
        }
        const std::string second_bytes = read_file_bytes(log_path);
        if (second_bytes.find(GEN2_MARKER) == std::string::npos)
        {
            std::fprintf(stderr, "generation 2 marker missing\n");
            return 31;
        }

        if (append_mode)
        {
            // An exact prefix proves that all generation-1 records survived before generation 2 wrote any bytes.
            if (second_bytes.size() <= first_bytes.size() ||
                second_bytes.compare(0, first_bytes.size(), first_bytes) != 0)
            {
                std::fprintf(stderr, "append mode did not preserve the generation-1 bytes as a prefix\n");
                return 32;
            }
        }
        else if (second_bytes.find(GEN1_MARKER) != std::string::npos)
        {
            std::fprintf(stderr, "default truncate mode preserved a generation-1 record\n");
            return 33;
        }

        return 0;
    }
} // anonymous namespace

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: logger_generation_log <append-preserves|truncate-default>\n");
        return 2;
    }

    const std::string_view scenario = argv[1];
    if (scenario == "append-preserves")
    {
        return run_scenario(/*append_mode=*/true);
    }
    if (scenario == "truncate-default")
    {
        return run_scenario(/*append_mode=*/false);
    }
    if (scenario == "child")
    {
        if (argc < 6)
        {
            std::fprintf(stderr, "child requires <route> <mode> <marker> <log-path>\n");
            return 12;
        }
        return run_child(argv[2], argv[3], argv[4], argv[5]);
    }

    std::fprintf(stderr, "unknown scenario token\n");
    return 2;
}
