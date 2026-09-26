/**
 * @file legacy_acp_paths.cpp
 * @brief Resolves config and log paths beside a module directory that the process code page cannot represent.
 * @details The MSVC image embeds legacy_acp.manifest, so the process uses the system legacy code page. The parent
 *          copies the image into a directory named U+7528 U+6237, or into one whose name holds an unpaired U+D800.
 *          It runs the copy with the tree root as its current directory. A config mode must resolve, load, reload,
 *          and watch the INI beside the copy. In a logger mode, a failed first sink open must leave a closed default,
 *          and a second configure must log beside the copy.
 *          Exit status is the oracle.
 */

#include "DetourModKit/config.hpp"
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/logger.hpp"
#include "internal/config_pass.hpp"

#include "raw_proof_error_mode.hpp"

#include <process.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

namespace
{
    constexpr int USAGE_EXIT_CODE = 2;
    constexpr int SKIP_EXIT_CODE = 77;
    constexpr std::string_view CHILD_TOKEN{"child"};
    constexpr DWORD CHILD_WAIT_MS = 45000;

    // The tree compiles without /utf-8, so non-ASCII characters appear only as escapes.
    constexpr wchar_t CJK_COMPONENT[] = L"\u7528\u6237";
    // The split literal ends the hex escape before the next character.
    constexpr wchar_t SURROGATE_COMPONENT[] = L"unpaired_\xD800"
                                              L"_surrogate";

    constexpr char INI_NAME[] = "legacy_acp.ini";
    constexpr wchar_t INI_NAME_WIDE[] = L"legacy_acp.ini";
    constexpr int DEFAULT_VALUE = 7;
    constexpr int DECOY_VALUE = 1;

    constexpr char FIRST_LOG_NAME[] = "missing_directory\\first.log";
    constexpr wchar_t FIRST_LOG_DIRECTORY_WIDE[] = L"missing_directory";
    constexpr char LOG_NAME[] = "legacy_acp.log";
    constexpr wchar_t LOG_NAME_WIDE[] = L"legacy_acp.log";
    constexpr std::string_view LOG_MARKER{"DMK_LEGACY_ACP_MARKER"};

    std::atomic<unsigned int> s_tree_counter{0};

    /** @brief The library surface that a mode drives in the copied child. */
    enum class Subject
    {
        Config,
        Logger
    };

    /** @brief The module directory name that a mode places the copy under. */
    enum class Component
    {
        /// Names the directory U+7528 U+6237, which a legacy code page outside the CJK locales cannot represent.
        Cjk,
        /// Names a directory with an unpaired U+D800, which no code page or strict UTF-8 conversion can represent.
        Surrogate
    };

    /** @brief One registered scenario and its argv token. */
    struct Mode
    {
        std::string_view token;
        Subject subject;
        Component component;
    };

    constexpr Mode MODES[] = {
        Mode{"config-cjk", Subject::Config, Component::Cjk},
        Mode{"config-surrogate", Subject::Config, Component::Surrogate},
        Mode{"logger-cjk", Subject::Logger, Component::Cjk},
        Mode{"logger-surrogate", Subject::Logger, Component::Surrogate},
    };

    /** @brief Returns the mode that @p token names, or nullptr for an unknown token. */
    [[nodiscard]] const Mode *find_mode(std::string_view token) noexcept
    {
        for (const Mode &mode : MODES)
        {
            if (mode.token == token)
            {
                return &mode;
            }
        }
        return nullptr;
    }

    /** @brief Returns the module directory name for @p component. */
    [[nodiscard]] const wchar_t *component_name(Component component) noexcept
    {
        return component == Component::Cjk ? CJK_COMPONENT : SURROGATE_COMPONENT;
    }

    /** @brief Reports the failed step and returns its exit code. */
    int fail(int code, const char *what) noexcept
    {
        std::fprintf(stderr, "FAIL: %s\n", what);
        return code;
    }

#if defined(_MSC_VER)
    /**
     * @brief Returns true when the image manifest requests the legacy code page.
     * @details An absent element means the build dropped the lane, so the CJK modes fail rather than skip.
     */
    [[nodiscard]] bool image_requests_legacy_code_page() noexcept
    {
        // The tree does not define UNICODE, so the call spells the narrow RT_MANIFEST macro as its value 24.
        const HRSRC resource = ::FindResourceW(nullptr, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(24));
        if (resource == nullptr)
        {
            return false;
        }
        const DWORD size = ::SizeofResource(nullptr, resource);
        const HGLOBAL loaded = ::LoadResource(nullptr, resource);
        const auto *const bytes = static_cast<const char *>(::LockResource(loaded));
        if (bytes == nullptr || size == 0)
        {
            return false;
        }
        const std::string_view text{bytes, size};
        return text.find("activeCodePage") != std::string_view::npos && text.find(">Legacy<") != std::string_view::npos;
    }

    /** @brief Returns true when the process code page encodes the CJK component without a default character. */
    [[nodiscard]] bool code_page_represents_component() noexcept
    {
        BOOL used_default = FALSE;
        const int bytes =
            ::WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, CJK_COMPONENT, -1, nullptr, 0, nullptr, &used_default);
        return bytes > 0 && used_default == FALSE;
    }
#endif

    /**
     * @brief Returns zero when a CJK mode can discriminate in this process, else the mode's exit code.
     * @details libstdc++ converts std::filesystem::path text through UTF-8. The MinGW image manifest has no
     *          activeCodePage element, so a MinGW build cannot reproduce the code-page decode that these modes detect.
     */
    [[nodiscard]] int check_cjk_lane()
    {
#if defined(_MSC_VER)
        if (!image_requests_legacy_code_page())
        {
            return fail(30, "the image carries no activeCodePage=Legacy manifest");
        }
        const UINT code_page = ::GetACP();
        if (code_page == CP_UTF8)
        {
            std::puts("SKIP: the OS ignored activeCodePage and left a UTF-8 process code page");
            return SKIP_EXIT_CODE;
        }
        if (code_page_represents_component())
        {
            std::printf("SKIP: code page %u represents the CJK component\n", code_page);
            return SKIP_EXIT_CODE;
        }
        return 0;
#else
        std::puts(
            "SKIP: libstdc++ converts std::filesystem::path through UTF-8 and the MinGW image embeds no Legacy manifest"
        );
        return SKIP_EXIT_CODE;
#endif
    }

    /** @brief Returns the wide path of this image, or an empty string on failure. */
    [[nodiscard]] std::wstring own_image_path()
    {
        std::wstring buffer(32768, L'\0');
        const DWORD length = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size())
        {
            return {};
        }
        buffer.resize(length);
        return buffer;
    }

    /** @brief Writes the proof INI with @p value through a wide path. */
    [[nodiscard]] bool write_ini(const std::filesystem::path &path, int value)
    {
        std::ofstream ini(path, std::ios::binary | std::ios::trunc);
        ini << "[Legacy]\r\nValue=" << value << "\r\n";
        ini.close();
        return static_cast<bool>(ini);
    }

    /** @brief Returns the bytes of @p path, or an empty string when it cannot be opened. */
    [[nodiscard]] std::string read_file_bytes(const std::filesystem::path &path)
    {
        std::ifstream stream(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    }

    /** @brief Removes the scenario tree on every parent exit path. */
    class TreeCleanup
    {
    public:
        explicit TreeCleanup(const std::filesystem::path &root) noexcept : m_root(root) {}

        TreeCleanup(const TreeCleanup &) = delete;
        TreeCleanup &operator=(const TreeCleanup &) = delete;

        ~TreeCleanup() noexcept
        {
            std::error_code ignored;
            std::filesystem::remove_all(m_root, ignored);
        }

    private:
        const std::filesystem::path &m_root;
    };

    /** @brief Stops the watcher and clears the registry before the captured atomics leave scope. */
    class ConfigRundown
    {
    public:
        ConfigRundown() = default;
        ConfigRundown(const ConfigRundown &) = delete;
        ConfigRundown &operator=(const ConfigRundown &) = delete;

        ~ConfigRundown() noexcept
        {
            DetourModKit::config::disable_auto_reload();
            DetourModKit::config::clear();
        }
    };

    /** @brief Runs @p copy as the child of @p mode in @p current_directory and returns its exit code. */
    [[nodiscard]] int
    run_copy(const std::filesystem::path &copy, const Mode &mode, const std::filesystem::path &current_directory)
    {
        std::wstring command_line =
            L"\"" + copy.native() + L"\" child " + std::wstring(mode.token.begin(), mode.token.end());
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        // The inherited standard handles carry the child's report into the CTest log.
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = ::GetStdHandle(STD_OUTPUT_HANDLE);
        startup.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
        PROCESS_INFORMATION process{};
        std::fflush(stdout);
        std::fflush(stderr);
        if (!::CreateProcessW(
                copy.c_str(),
                command_line.data(),
                nullptr,
                nullptr,
                TRUE,
                0,
                nullptr,
                current_directory.c_str(),
                &startup,
                &process
            ))
        {
            return fail(34, "CreateProcessW on the copy");
        }
        ::CloseHandle(process.hThread);
        if (::WaitForSingleObject(process.hProcess, CHILD_WAIT_MS) != WAIT_OBJECT_0)
        {
            ::TerminateProcess(process.hProcess, 1);
            // The image stays locked until the process ends, and the tree cleanup deletes it.
            ::WaitForSingleObject(process.hProcess, 5000);
            ::CloseHandle(process.hProcess);
            return fail(35, "the child did not exit");
        }
        DWORD exit_code = 1;
        ::GetExitCodeProcess(process.hProcess, &exit_code);
        ::CloseHandle(process.hProcess);
        if (exit_code != 0)
        {
            std::fprintf(stderr, "FAIL: the child exited with %lu\n", exit_code);
        }
        return static_cast<int>(exit_code);
    }

    /** @brief Checks that the child logged the marker to the sink beside the copy. */
    [[nodiscard]] int check_marker(const std::filesystem::path &log_path)
    {
        std::error_code error;
        if (!std::filesystem::exists(log_path, error))
        {
            return fail(37, "no log file beside the copy");
        }
        if (read_file_bytes(log_path).find(LOG_MARKER) == std::string::npos)
        {
            return fail(38, "the log file beside the copy lacks the marker");
        }
        return 0;
    }

    /** @brief Returns true when a status query reports that @p path does not exist. */
    [[nodiscard]] bool path_is_absent(const std::filesystem::path &path) noexcept
    {
        // A failed query reports a type other than not_found, so an unreadable status counts as present.
        std::error_code error;
        return std::filesystem::status(path, error).type() == std::filesystem::file_type::not_found;
    }

    /**
     * @brief Stages the copy for @p mode, runs it, and checks what a logger mode leaves in the tree.
     * @details The copy runs from the tree root. A config mode writes a decoy INI there.
     */
    int run_parent(const Mode &mode)
    {
        if (mode.component == Component::Cjk)
        {
            const int lane = check_cjk_lane();
            if (lane != 0)
            {
                return lane;
            }
        }

        std::error_code error;
        const std::filesystem::path temp = std::filesystem::temp_directory_path(error);
        if (error)
        {
            return fail(31, "resolve the temporary directory");
        }
        const std::filesystem::path root =
            temp / (L"dmk_legacy_acp_" + std::to_wstring(_getpid()) + L"_" + std::to_wstring(s_tree_counter++));
        const TreeCleanup cleanup{root};
        // A killed earlier run under this reused PID leaves its tree behind, which the strict create rejects.
        std::error_code stale_tree_error;
        std::filesystem::remove_all(root, stale_tree_error);
        const std::filesystem::path module_directory = root / component_name(mode.component);
        if (!std::filesystem::create_directories(module_directory, error) || error)
        {
            return fail(31, "create the module directory");
        }

        const std::wstring self = own_image_path();
        const std::filesystem::path copy = module_directory / std::filesystem::path(self).filename();
        if (self.empty() || !::CopyFileW(self.c_str(), copy.c_str(), TRUE))
        {
            return fail(32, "copy the image into the module directory");
        }

        if (mode.subject == Subject::Config)
        {
            if (!write_ini(module_directory / INI_NAME_WIDE, 42))
            {
                return fail(33, "write the INI beside the copy");
            }
            // A fallback to the current directory reads the decoy value instead of the defaults.
            if (!write_ini(root / INI_NAME_WIDE, DECOY_VALUE))
            {
                return fail(36, "write the decoy INI into the tree root");
            }
        }

        const int child_exit = run_copy(copy, mode, root);
        if (child_exit != 0 || mode.subject == Subject::Config)
        {
            return child_exit;
        }
        // The failed first open must create no directory beside the copy or in the working directory.
        if (!path_is_absent(module_directory / FIRST_LOG_DIRECTORY_WIDE) ||
            !path_is_absent(root / FIRST_LOG_DIRECTORY_WIDE))
        {
            return fail(39, "the failed first open created its log directory");
        }
        return check_marker(module_directory / LOG_NAME_WIDE);
    }

    /** @brief Reports the value a failed step observed and returns its exit code. */
    int fail_with_value(int code, const char *what, int observed) noexcept
    {
        std::fprintf(stderr, "FAIL: %s (value %d, decoy %d, default %d)\n", what, observed, DECOY_VALUE, DEFAULT_VALUE);
        return code;
    }

    /** @brief Verifies resolve, load, reload, and the watcher against the INI beside @p module_directory. */
    int run_config_child(const std::filesystem::path &module_directory)
    {
        namespace config = DetourModKit::config;
        const std::filesystem::path expected = (module_directory / INI_NAME_WIDE).lexically_normal();

        config::detail::DeferredDiagnostics diagnostics = config::detail::open_deferred_diagnostics();
        std::filesystem::path resolved;
        try
        {
            resolved = config::detail::get_ini_file_path(INI_NAME, diagnostics);
        }
        catch (const std::exception &)
        {
            return fail(13, "get_ini_file_path threw");
        }
        if (!resolved.is_absolute() || resolved.native() != expected.native())
        {
            return fail(14, "get_ini_file_path did not return the INI beside the module");
        }

        // The setter and the watcher callback capture these, so they must outlive the rundown.
        std::atomic<int> value{-1};
        std::atomic<bool> fired{false};
        const ConfigRundown rundown{};
        config::bind_int(
            "Legacy",
            "Value",
            "Legacy value",
            [&value](int parsed) { value.store(parsed); },
            DEFAULT_VALUE
        );
        try
        {
            config::load(INI_NAME);
        }
        catch (const std::exception &)
        {
            return fail(15, "load threw");
        }
        if (value.load() != 42)
        {
            return fail_with_value(16, "load did not read the INI beside the module", value.load());
        }

        if (!write_ini(expected, 43))
        {
            return fail(17, "rewrite the INI for reload");
        }
        bool reloaded = false;
        try
        {
            reloaded = config::reload();
        }
        catch (const std::exception &)
        {
            return fail(18, "reload threw");
        }
        if (!reloaded || value.load() != 43)
        {
            return fail_with_value(19, "reload did not read the INI beside the module", value.load());
        }

        config::AutoReloadStatus status = config::AutoReloadStatus::StartFailed;
        try
        {
            status = config::enable_auto_reload(
                std::chrono::milliseconds{50},
                [&fired](bool setters_ran) -> void
                {
                    if (setters_ran)
                    {
                        fired.store(true);
                    }
                }
            );
        }
        catch (const std::exception &)
        {
            return fail(20, "enable_auto_reload threw");
        }
        if (status != config::AutoReloadStatus::Started)
        {
            return fail(21, "the watcher did not start");
        }
        if (!write_ini(expected, 44))
        {
            return fail(23, "rewrite the INI for the watcher");
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
        while (!(fired.load() && value.load() == 44) && std::chrono::steady_clock::now() < deadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
        }
        if (!(fired.load() && value.load() == 44))
        {
            return fail_with_value(22, "the watcher missed the INI beside the module", value.load());
        }
        return 0;
    }

    /** @brief Fails the first sink open, requires a closed default, then reconfigures it and logs the marker. */
    int run_logger_child()
    {
        // The first open fails under an absent directory, so its failure diagnostic runs inside first-use construction.
        try
        {
            DetourModKit::Logger::configure("LegacyAcp", FIRST_LOG_NAME);
        }
        catch (const std::exception &)
        {
            return fail(24, "the first configure threw");
        }
        // No level filter drops an Error record, so a false result means the closed default refused it.
        if (DetourModKit::log().log_noexcept(DetourModKit::LogLevel::Error, "DMK_LEGACY_ACP_PREMISE"))
        {
            return fail(27, "the first configure left a sink that accepts records");
        }
        try
        {
            DetourModKit::Logger::configure("LegacyAcp", LOG_NAME);
        }
        catch (const std::exception &)
        {
            return fail(25, "the second configure threw");
        }
        try
        {
            DetourModKit::log().info("{}", LOG_MARKER);
        }
        catch (const std::exception &)
        {
            return fail(26, "the marker record threw");
        }
        DetourModKit::log().shutdown();
        return 0;
    }

    /** @brief Reports the process code page and runs the subject of @p mode inside the copy. */
    int run_child(const Mode &mode)
    {
        const UINT code_page = ::GetACP();
        std::printf(
            "child %.*s: process code page %u\n",
            static_cast<int>(mode.token.size()),
            mode.token.data(),
            code_page
        );
        std::fflush(stdout);
        if (mode.component == Component::Cjk && code_page == CP_UTF8)
        {
            return fail(11, "the copy runs with a UTF-8 process code page");
        }
        const std::filesystem::path module_directory{DetourModKit::filesystem::get_runtime_directory()};
        if (module_directory.native().find(component_name(mode.component)) == std::wstring::npos)
        {
            return fail(12, "the module directory lacks the scenario component");
        }
        return mode.subject == Subject::Config ? run_config_child(module_directory) : run_logger_child();
    }
} // namespace

int main(int argc, char **argv)
{
    dmk_lifecycle::configure_raw_proof_error_mode();
    const Mode *mode = nullptr;
    if (argc == 2)
    {
        mode = find_mode(argv[1]);
        if (mode != nullptr)
        {
            return run_parent(*mode);
        }
    }
    else if (argc == 3 && std::string_view{argv[1]} == CHILD_TOKEN)
    {
        mode = find_mode(argv[2]);
        if (mode != nullptr)
        {
            return run_child(*mode);
        }
    }
    std::fprintf(stderr, "usage: legacy_acp_paths <config-cjk|config-surrogate|logger-cjk|logger-surrogate>\n");
    return USAGE_EXIT_CODE;
}
