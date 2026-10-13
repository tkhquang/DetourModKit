#ifndef DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_HOST_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_HOST_HPP

#include "staged_generation_protocol.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <process.h>
#include <windows.h>

/**
 * @file staged_generation_host.hpp
 * @brief Host-side staging, loading, and unmap checks for staged generation copies.
 * @details A host stages copies of @ref staged_gen::SOURCE_MODULE_NAME from the working directory. The CTest fixture
 *          dmk_staged_generation_artifacts removes the staged copies and the log files that these names produce. A
 *          host can load one staged copy again after it unmaps.
 */

namespace staged_gen
{
    /// Bounds the staged names that one process tries before stage_copy fails.
    inline constexpr unsigned STAGED_COPY_CANDIDATE_LIMIT = 1024;

    inline constexpr DWORD UNLOAD_POLL_BUDGET_MS = 3000;
    inline constexpr DWORD UNLOAD_POLL_STEP_MS = 10;

    /// Reports whether a mapped module owns @p address. The reference count of that module does not change.
    [[nodiscard]] inline bool module_owns(const void *address) noexcept
    {
        HMODULE owner = nullptr;
        const BOOL ok = ::GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address),
            &owner
        );
        return ok != FALSE && owner != nullptr;
    }

    /// Polls until no module owns @p marker or UNLOAD_POLL_BUDGET_MS expires, and returns true after the unmap.
    [[nodiscard]] inline bool wait_for_unmap(const void *marker) noexcept
    {
        DWORD waited = 0;
        while (module_owns(marker) && waited < UNLOAD_POLL_BUDGET_MS)
        {
            ::Sleep(UNLOAD_POLL_STEP_MS);
            waited += UNLOAD_POLL_STEP_MS;
        }
        return !module_owns(marker);
    }

    /**
     * @struct Generation
     * @brief One staged copy and every export the hosts drive.
     * @details The path stays after an unload, so load_staged_generation can map the same copy again.
     */
    struct Generation
    {
        std::filesystem::path path;
        HMODULE module = nullptr;
        const void *marker = nullptr;
        InitFn init = nullptr;
        ShutdownFn shutdown = nullptr;
        TagFn tag = nullptr;
        StatusFn status = nullptr;
        ArmParkFn arm_park = nullptr;
        ReleaseParkFn release_park = nullptr;
        WaitParkedFn wait_parked = nullptr;

        [[nodiscard]] Status read_status() const noexcept
        {
            Status snapshot{};
            status(&snapshot);
            return snapshot;
        }
    };

    template <class Fn> [[nodiscard]] Fn resolve(HMODULE module, const char *symbol) noexcept
    {
        return reinterpret_cast<Fn>(reinterpret_cast<void *>(::GetProcAddress(module, symbol)));
    }

    /// Builds a staged-generation path from the current process ID and @p nonce.
    [[nodiscard]] inline std::filesystem::path
    make_staged_generation_path(const std::filesystem::path &directory, unsigned nonce)
    {
        return directory / ("staged_generation.p" + std::to_string(static_cast<unsigned long>(_getpid())) + "_g" +
                            std::to_string(nonce) + ".dll");
    }

    /// Builds a per-process unique log file name. A @p stem that starts with "staged_gen_" matches the cleanup.
    [[nodiscard]] inline std::string make_log_name(std::string_view stem)
    {
        static std::atomic<unsigned> s_counter{0};
        const unsigned nonce = s_counter.fetch_add(1, std::memory_order_relaxed);
        return std::string{stem} + ".p" + std::to_string(static_cast<unsigned long>(_getpid())) + "_n" +
               std::to_string(nonce) + ".log";
    }

    /// Copies the source image to a per-process unique name and rewrites the tag bytes to @p tag_value.
    [[nodiscard]] inline bool stage_copy(const std::string &tag_value, std::filesystem::path &staged)
    {
        static std::atomic<unsigned> s_counter{0};
        std::error_code error;
        const std::filesystem::path source = std::filesystem::current_path(error) / SOURCE_MODULE_NAME;
        if (error)
        {
            std::fprintf(stderr, "stage_copy: current_path failed: %s (%d)\n", error.message().c_str(), error.value());
            return false;
        }

        bool copied = false;
        for (unsigned attempt = 0; attempt < STAGED_COPY_CANDIDATE_LIMIT; ++attempt)
        {
            const unsigned nonce = s_counter.fetch_add(1, std::memory_order_relaxed);
            std::filesystem::path candidate = make_staged_generation_path(source.parent_path(), nonce);
            error.clear();
            if (std::filesystem::copy_file(source, candidate, error))
            {
                staged = std::move(candidate);
                copied = true;
                break;
            }
            if (error != std::errc::file_exists)
            {
                std::fprintf(
                    stderr,
                    "stage_copy: copy_file failed for %s: %s (%d)\n",
                    candidate.string().c_str(),
                    error.message().c_str(),
                    error.value()
                );
                return false;
            }
        }
        if (!copied)
        {
            std::fprintf(stderr, "stage_copy: no free candidate after %u attempts\n", STAGED_COPY_CANDIDATE_LIMIT);
            return false;
        }

        std::fstream file(staged, std::ios::in | std::ios::out | std::ios::binary);
        if (!file)
        {
            std::fprintf(stderr, "stage_copy: open failed for %s\n", staged.string().c_str());
            return false;
        }
        // One bulk read. A per-character read of the coverage-instrumented copy costs seconds per generation.
        file.seekg(0, std::ios::end);
        const std::streamoff staged_size = file.tellg();
        if (staged_size <= 0)
        {
            std::fprintf(stderr, "stage_copy: size read failed for %s\n", staged.string().c_str());
            return false;
        }
        file.seekg(0, std::ios::beg);
        std::vector<char> bytes(static_cast<std::size_t>(staged_size));
        if (!file.read(bytes.data(), staged_size))
        {
            std::fprintf(stderr, "stage_copy: image read failed for %s\n", staged.string().c_str());
            return false;
        }
        const std::string_view needle{TAG_MARKER};
        const auto found = std::string_view{bytes.data(), bytes.size()}.find(needle);
        if (found == std::string_view::npos)
        {
            std::fprintf(stderr, "stage_copy: tag marker missing from %s\n", staged.string().c_str());
            return false;
        }
        const std::size_t tag_at = found + needle.size();
        if (tag_at + TAG_LENGTH > bytes.size())
        {
            std::fprintf(stderr, "stage_copy: tag range exceeds %s\n", staged.string().c_str());
            return false;
        }
        for (std::size_t i = 0; i < TAG_LENGTH; ++i)
        {
            bytes[tag_at + i] = i < tag_value.size() ? tag_value[i] : '0';
        }
        file.seekp(static_cast<std::streamoff>(tag_at), std::ios::beg);
        file.write(bytes.data() + tag_at, static_cast<std::streamsize>(TAG_LENGTH));
        if (!file)
        {
            std::fprintf(stderr, "stage_copy: tag write failed for %s\n", staged.string().c_str());
            return false;
        }
        return true;
    }

    /**
     * @brief Maps the staged copy at Generation::path and resolves every export.
     * @details A copy that unmapped maps again from the same file. Real-time antivirus scanning slows the first load
     *          of each fresh copy, so a long loop stages each family once and loads it again.
     * @return False when the generation is still loaded, LoadLibrary fails, or an export is missing.
     */
    [[nodiscard]] inline bool load_staged_generation(Generation &generation)
    {
        if (generation.module != nullptr)
        {
            return false;
        }
        Generation loaded{};
        loaded.path = generation.path;
        loaded.module = ::LoadLibraryW(generation.path.c_str());
        if (loaded.module == nullptr)
        {
            return false;
        }
        loaded.marker = reinterpret_cast<const void *>(::GetProcAddress(loaded.module, MARKER_SYMBOL));
        loaded.init = resolve<InitFn>(loaded.module, INIT_SYMBOL);
        loaded.shutdown = resolve<ShutdownFn>(loaded.module, SHUTDOWN_SYMBOL);
        loaded.tag = resolve<TagFn>(loaded.module, TAG_SYMBOL);
        loaded.status = resolve<StatusFn>(loaded.module, STATUS_SYMBOL);
        loaded.arm_park = resolve<ArmParkFn>(loaded.module, ARM_PARK_SYMBOL);
        loaded.release_park = resolve<ReleaseParkFn>(loaded.module, RELEASE_PARK_SYMBOL);
        loaded.wait_parked = resolve<WaitParkedFn>(loaded.module, WAIT_PARKED_SYMBOL);
        generation = std::move(loaded);
        return generation.marker != nullptr && generation.init != nullptr && generation.shutdown != nullptr &&
               generation.tag != nullptr && generation.status != nullptr && generation.arm_park != nullptr &&
               generation.release_park != nullptr && generation.wait_parked != nullptr;
    }

    /// Stages a fresh copy tagged @p tag_value and loads it.
    [[nodiscard]] inline bool load_generation(const std::string &tag_value, Generation &generation)
    {
        return stage_copy(tag_value, generation.path) && load_staged_generation(generation);
    }

    /// Drops the host loader reference. The path stays for a later load_staged_generation.
    [[nodiscard]] inline bool unload_generation(Generation &generation) noexcept
    {
        if (generation.module == nullptr)
        {
            return true;
        }
        if (::FreeLibrary(generation.module) == 0)
        {
            return false;
        }
        generation.module = nullptr;
        return true;
    }

    inline void remove_unmapped_staged_file_best_effort(const Generation &generation) noexcept
    {
        std::error_code error;
        (void)std::filesystem::remove(generation.path, error);
    }

    /**
     * @brief Sums the committed private PAGE_EXECUTE_READWRITE bytes of this process.
     * @details The backend allocator commits its trampoline blocks with this protection. The trap gateway of each
     *          backend copy is PAGE_EXECUTE_READ and stays after its image unmaps, so the census leaves it out.
     * @return UINT64_MAX when a query fails.
     */
    [[nodiscard]] inline std::uint64_t committed_private_execute_read_write_bytes() noexcept
    {
        // The low byte holds the base protection. PAGE_GUARD and the cache modifiers sit above it.
        constexpr DWORD BASE_PROTECTION_MASK = 0xFF;
        SYSTEM_INFO system{};
        ::GetSystemInfo(&system);
        const auto limit = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
        std::uint64_t bytes = 0;
        for (std::uintptr_t cursor = 0; cursor < limit;)
        {
            MEMORY_BASIC_INFORMATION region{};
            if (::VirtualQuery(reinterpret_cast<const void *>(cursor), &region, sizeof(region)) != sizeof(region))
            {
                return UINT64_MAX;
            }
            if (region.State == MEM_COMMIT && region.Type == MEM_PRIVATE &&
                (region.Protect & BASE_PROTECTION_MASK) == PAGE_EXECUTE_READWRITE)
            {
                bytes += region.RegionSize;
            }
            const auto next = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
            if (next <= cursor)
            {
                return UINT64_MAX;
            }
            cursor = next;
        }
        return bytes;
    }
} // namespace staged_gen

#endif // DETOURMODKIT_TESTS_LIFECYCLE_STAGED_GENERATION_HOST_HPP
