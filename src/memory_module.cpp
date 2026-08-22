/**
 * @file memory_module.cpp
 * @brief Provides module presence and address ownership queries.
 */

#include "DetourModKit/memory.hpp"
#include "internal/memory_representation_win32.hpp"
#include "internal/module_name.hpp"
#include "platform.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <string>
#include <string_view>

namespace DetourModKit
{
    namespace detail
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        void (*g_module_loaded_after_reference_test_hook)() noexcept = nullptr;
        HMODULE g_module_loaded_reference_candidate_test_override = nullptr;
#endif

        // The canonical module-base -> Region resolver (declared in internal/memory_guarded.hpp). Both region.cpp's
        // Region factories (host/module_named/own) and memory::module_of route through this one definition, so the
        // PE-header walk (DOS magic, a bounded e_lfanew, the NT signature, and OptionalHeader.SizeOfImage) has a
        // single source of truth. Reads go through the guarded engine (memory::read), so a partially-mapped or corrupt
        // image fails closed to an empty Region rather than faulting the host. The walk is repeated per call rather
        // than memoized per handle: an HMODULE IS its image base and Windows reuses it after an unload, so any cached
        // span is a claim about an identity the loader can reassign, and a completed same-base replacement carrying a
        // different SizeOfImage would keep serving the previous image's extent from this public query.
        Region module_image_region(Address module_base) noexcept
        {
            if (!module_base)
            {
                return Region{};
            }

            const auto dos = memory::read<IMAGE_DOS_HEADER>(module_base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            {
                return Region{};
            }

            // Bound e_lfanew. A genuine PE places its NT headers within the first few KiB; anything beyond a generous
            // 1 MiB cap is corrupt or hostile.
            if (dos->e_lfanew <= 0 || static_cast<std::uint32_t>(dos->e_lfanew) > 0x100000U)
            {
                return Region{};
            }

            const auto nt = memory::read<IMAGE_NT_HEADERS>(module_base.offset(dos->e_lfanew));
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return Region{};
            }

            const std::size_t size_of_image = static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage);
            if (size_of_image == 0)
            {
                return Region{};
            }

            return Region{module_base, size_of_image};
        }

        Region live_module_region(Address address) noexcept
        {
            if (!address)
                return Region{};

            HMODULE owning_module = nullptr;
            if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      address.as<LPCWSTR>(), &owning_module) ||
                owning_module == nullptr)
                return Region{};
            return module_image_region(Address{owning_module});
        }
    } // namespace detail

    namespace
    {
        inline constexpr std::size_t MAX_MODULE_PATH_CHARS = 32768;

        class ScopedModuleReference
        {
        public:
            explicit ScopedModuleReference(HMODULE module) noexcept : m_module{module} {}
            ~ScopedModuleReference() noexcept
            {
                if (m_module != nullptr)
                {
                    (void)::FreeLibrary(m_module);
                }
            }

            ScopedModuleReference(const ScopedModuleReference &) = delete;
            ScopedModuleReference &operator=(const ScopedModuleReference &) = delete;
            ScopedModuleReference(ScopedModuleReference &&) = delete;
            ScopedModuleReference &operator=(ScopedModuleReference &&) = delete;

        private:
            HMODULE m_module;
        };

        class ScopedSnapshot
        {
        public:
            explicit ScopedSnapshot(HANDLE snapshot) noexcept : m_snapshot{snapshot} {}
            ~ScopedSnapshot() noexcept { (void)::CloseHandle(m_snapshot); }

            ScopedSnapshot(const ScopedSnapshot &) = delete;
            ScopedSnapshot &operator=(const ScopedSnapshot &) = delete;
            ScopedSnapshot(ScopedSnapshot &&) = delete;
            ScopedSnapshot &operator=(ScopedSnapshot &&) = delete;

        private:
            HANDLE m_snapshot;
        };

        [[nodiscard]] bool module_basename_matches(HMODULE module, std::wstring_view expected) noexcept
        {
            try
            {
                std::wstring module_path;
                DWORD length = 0;
                std::size_t capacity = MAX_PATH;
                while (true)
                {
                    module_path.resize(capacity);
                    length = ::GetModuleFileNameW(module, module_path.data(), static_cast<DWORD>(capacity));
                    if (length == 0)
                    {
                        return false;
                    }
                    if (length < capacity)
                    {
                        break;
                    }
                    if (capacity >= MAX_MODULE_PATH_CHARS)
                    {
                        return false;
                    }
                    capacity = (capacity <= MAX_MODULE_PATH_CHARS / 2) ? capacity * 2 : MAX_MODULE_PATH_CHARS;
                }

                const std::wstring_view path_view{module_path.data(), length};
                const std::size_t separator = path_view.find_last_of(L"\\/");
                const std::wstring_view actual =
                    (separator == std::wstring_view::npos) ? path_view : path_view.substr(separator + 1);
                return actual == expected;
            }
            catch (...)
            {
                return false;
            }
        }

        [[nodiscard]] bool module_name_matches_insensitive(const wchar_t *actual, std::wstring_view expected) noexcept
        {
            if (expected.size() > static_cast<std::size_t>(INT_MAX))
            {
                return false;
            }
            return ::CompareStringOrdinal(actual, -1, expected.data(), static_cast<int>(expected.size()), TRUE) ==
                   CSTR_EQUAL;
        }

        [[nodiscard]] HANDLE create_module_snapshot() noexcept
        {
            constexpr int max_attempts = 3;
            for (int attempt = 0; attempt < max_attempts; ++attempt)
            {
                const HANDLE snapshot =
                    ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ::GetCurrentProcessId());
                if (snapshot != INVALID_HANDLE_VALUE)
                {
                    return snapshot;
                }
                if (::GetLastError() != ERROR_BAD_LENGTH)
                {
                    break;
                }
            }
            return INVALID_HANDLE_VALUE;
        }

        [[nodiscard]] bool any_module_basename_matches(std::wstring_view expected) noexcept
        {
            const HANDLE raw_snapshot = create_module_snapshot();
            if (raw_snapshot == INVALID_HANDLE_VALUE)
            {
                return false;
            }
            const ScopedSnapshot snapshot{raw_snapshot};

            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            if (::Module32FirstW(raw_snapshot, &entry) == FALSE)
            {
                return false;
            }

            do
            {
                if (!module_name_matches_insensitive(entry.szModule, expected))
                {
                    continue;
                }

                HMODULE module = nullptr;
                if (::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                         reinterpret_cast<LPCWSTR>(entry.modBaseAddr), &module) == FALSE ||
                    module == nullptr)
                {
                    continue;
                }
                const ScopedModuleReference reference{module};
                if (module_basename_matches(module, expected))
                {
                    return true;
                }
            } while (::Module32NextW(raw_snapshot, &entry) != FALSE);

            return false;
        }
    } // namespace

    namespace memory
    {
        Region module_of(Address address) noexcept
        {
            return detail::live_module_region(address);
        }

        bool is_module_loaded(std::string_view basename, bool case_insensitive) noexcept
        {
            const std::wstring wide_name = detail::widen_module_name(basename);
            if (wide_name.empty())
            {
                return false;
            }

            if (case_insensitive)
            {
                return ::GetModuleHandleW(wide_name.c_str()) != nullptr;
            }
            if (detail::is_loader_lock_held())
            {
                return false;
            }

            HMODULE module = nullptr;
            BOOL reference_acquired = FALSE;
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (DetourModKit::detail::g_module_loaded_reference_candidate_test_override != nullptr)
            {
                reference_acquired = ::GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    reinterpret_cast<LPCWSTR>(DetourModKit::detail::g_module_loaded_reference_candidate_test_override),
                    &module);
            }
            else
#endif
            {
                reference_acquired = ::GetModuleHandleExW(0, wide_name.c_str(), &module);
            }
            if (reference_acquired == FALSE || module == nullptr)
            {
                return false;
            }
            const ScopedModuleReference reference{module};

#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *const hook = DetourModKit::detail::g_module_loaded_after_reference_test_hook)
            {
                hook();
            }
#endif

            if (module_basename_matches(module, wide_name))
            {
                return true;
            }
            return any_module_basename_matches(wide_name);
        }
    } // namespace memory
} // namespace DetourModKit
