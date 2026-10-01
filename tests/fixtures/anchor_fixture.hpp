#ifndef DETOURMODKIT_TESTS_FIXTURES_ANCHOR_FIXTURE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_ANCHOR_FIXTURE_HPP

/**
 * @file anchor_fixture.hpp
 * @brief Shares synthetic images, the export loader, and anchor helpers across the split suites.
 * @details docs/design/testing.md owns the shared-fixture rule.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "DetourModKit/address.hpp"
#include "DetourModKit/anchor.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"
#include "fixtures/scratch_page.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string_view>

namespace dmk_test::anchor_fixture
{
    namespace dmk = DetourModKit;
    namespace an = DetourModKit::anchor;
    namespace sc = DetourModKit::scan;

    /**
     * @brief Compiles an AOB literal that the fixture already proves valid.
     * @param dsl A valid pattern because this helper unwraps the result without a failure arm.
     */
    [[nodiscard]] inline sc::Pattern aob(std::string_view dsl)
    {
        return sc::Pattern::compile(dsl).value();
    }

    using dmk_test::ScratchPage;

    /** @brief Keeps a string and its RIP-relative reference inside one committed executable Region. */
    class StringImage
    {
    public:
        StringImage()
        {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            m_size = si.dwPageSize;
            m_base = static_cast<std::uint8_t *>(
                VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            );
        }

        ~StringImage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        StringImage(const StringImage &) = delete;
        StringImage &operator=(const StringImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        void write_string(std::size_t off, std::string_view text) noexcept
        {
            std::memcpy(m_base + off, text.data(), text.size());
            m_base[off + text.size()] = 0x00; // NUL terminator so require_terminator matches
        }

        /** @brief Plants `48 <opcode> 05 <disp32>` with a RIP-relative target and rax destination. */
        void plant_rip_load(std::size_t instr_off, std::size_t target_off, std::uint8_t opcode) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x48; // REX.W
            p[1] = opcode;
            p[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        /** @brief Plants `48 89 05 <disp32>` for the store shape that StringPointerSlot decodes. */
        void plant_rip_store(std::size_t instr_off, std::size_t slot_off) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x48; // REX.W
            p[1] = 0x89; // mov r/m64, r64
            p[2] = 0x05; // ModRM: mod=00, reg=rax, rm=101 (RIP-relative)
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 7);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(slot_off)) - next);
            std::memcpy(p + 3, &disp, sizeof(disp));
        }

        /** @brief Plants the no-REX `8D 05 <disp32>` reference that only the broad sweep recognizes. */
        void plant_broad_only_rip_load(std::size_t instr_off, std::size_t target_off) noexcept
        {
            std::uint8_t *p = m_base + instr_off;
            p[0] = 0x8D;
            p[1] = 0x05;
            const auto next = static_cast<std::int64_t>(addr(instr_off) + 6);
            const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(addr(target_off)) - next);
            std::memcpy(p + 2, &disp, sizeof(disp));
        }

        void put(std::size_t off, std::initializer_list<std::uint8_t> bytes) noexcept
        {
            std::uint8_t *p = m_base + off;
            std::size_t i = 0;
            for (const std::uint8_t byte : bytes)
            {
                p[i++] = byte;
            }
        }

        [[nodiscard]] std::uintptr_t addr(std::size_t off) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + off);
        }

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }

    private:
        std::uint8_t *m_base = nullptr;
        std::size_t m_size = 0;
    };

    /** @brief Refuses the post-resolve value through the exact noexcept AnchorValidator type. */
    inline bool always_reject(std::int64_t, const void *) noexcept
    {
        return false;
    }

    /** @brief Loads the fixture DLL by basename from the test executable directory. */
    class ExportFixture
    {
    public:
        ExportFixture() : m_handle(LoadLibraryA(MODULE_NAME)) {}
        ExportFixture(const ExportFixture &) = delete;
        ExportFixture &operator=(const ExportFixture &) = delete;
        ~ExportFixture()
        {
            if (m_handle != nullptr)
            {
                FreeLibrary(m_handle);
            }
        }

        [[nodiscard]] bool ok() const noexcept { return m_handle != nullptr; }

        /** @brief Returns the loader-assigned export address that resolve_export must reproduce. */
        [[nodiscard]] std::uintptr_t proc(const char *name) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(GetProcAddress(m_handle, name));
        }

        static constexpr const char *MODULE_NAME = "hook_target_lib.dll";

    private:
        HMODULE m_handle{};
    };

    /** @brief Maps malformed PE64 export data that the normal loader refuses. */
    class SyntheticExportImage
    {
    public:
        static constexpr std::size_t IMAGE_BYTES = 0x2000;
        static constexpr std::uint32_t NT_RVA = 0x100;
        static constexpr std::uint32_t EXPORT_RVA = 0x300;
        static constexpr std::uint32_t EXPORT_BYTES = 0x200;
        static constexpr std::uint32_t FUNCTIONS_RVA = 0x600;
        static constexpr std::uint32_t NAMES_RVA = 0x700;
        static constexpr std::uint32_t ORDINALS_RVA = 0x800;
        static constexpr std::uint32_t NAME_RVA = 0x900;
        static constexpr std::uint32_t TARGET_RVA = 0x1000;

        SyntheticExportImage() : m_base(VirtualAlloc(nullptr, IMAGE_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
        {
            if (m_base == nullptr)
            {
                return;
            }
            std::memset(m_base, 0, IMAGE_BYTES);

            IMAGE_DOS_HEADER dos{};
            dos.e_magic = IMAGE_DOS_SIGNATURE;
            dos.e_lfanew = static_cast<LONG>(NT_RVA);
            put(0, dos);

            IMAGE_NT_HEADERS64 nt{};
            nt.Signature = IMAGE_NT_SIGNATURE;
            nt.FileHeader.NumberOfSections = 1;
            nt.FileHeader.SizeOfOptionalHeader = static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER64));
            nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
            nt.OptionalHeader.SizeOfImage = static_cast<DWORD>(IMAGE_BYTES);
            nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {EXPORT_RVA, EXPORT_BYTES};
            put(NT_RVA, nt);

            IMAGE_SECTION_HEADER section{};
            std::memcpy(section.Name, ".text", 5);
            section.Misc.VirtualSize = 0x1000;
            section.VirtualAddress = 0x1000;
            section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
            put(NT_RVA + sizeof(IMAGE_NT_HEADERS64), section);

            IMAGE_EXPORT_DIRECTORY exports{};
            exports.Base = 1;
            exports.NumberOfFunctions = 1;
            exports.NumberOfNames = 1;
            exports.AddressOfFunctions = FUNCTIONS_RVA;
            exports.AddressOfNames = NAMES_RVA;
            exports.AddressOfNameOrdinals = ORDINALS_RVA;
            put(EXPORT_RVA, exports);

            put(FUNCTIONS_RVA, TARGET_RVA);
            put(NAMES_RVA, NAME_RVA);
            put(ORDINALS_RVA, std::uint16_t{0});
            put_string(NAME_RVA, "fixture_export");
        }

        ~SyntheticExportImage()
        {
            if (m_base != nullptr)
            {
                VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        SyntheticExportImage(const SyntheticExportImage &) = delete;
        SyntheticExportImage &operator=(const SyntheticExportImage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }

        template <typename T> void put(std::size_t offset, const T &value)
        {
            ASSERT_LE(offset + sizeof(T), IMAGE_BYTES);
            std::memcpy(static_cast<std::byte *>(m_base) + offset, &value, sizeof(T));
        }

        template <typename T> [[nodiscard]] T get(std::size_t offset) const
        {
            EXPECT_LE(offset + sizeof(T), IMAGE_BYTES);
            T value{};
            std::memcpy(&value, static_cast<const std::byte *>(m_base) + offset, sizeof(T));
            return value;
        }

        void put_string(std::size_t offset, std::string_view value)
        {
            ASSERT_LE(offset + value.size() + 1, IMAGE_BYTES);
            std::memcpy(static_cast<std::byte *>(m_base) + offset, value.data(), value.size());
            static_cast<char *>(m_base)[offset + value.size()] = '\0';
        }

        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, IMAGE_BYTES};
        }

        [[nodiscard]] bool protect_no_access(std::size_t offset) noexcept
        {
            if (m_base == nullptr || offset >= IMAGE_BYTES)
            {
                return false;
            }
            DWORD old_protection = 0;
            return VirtualProtect(
                       static_cast<std::byte *>(m_base) + offset,
                       IMAGE_BYTES - offset,
                       PAGE_NOACCESS,
                       &old_protection
                   ) != FALSE;
        }

    private:
        void *m_base{};
    };

    /** @brief Supplies the kind and status that a synthetic drift report needs for gate checks. */
    [[nodiscard]] inline an::ResolvedAnchor ra(an::AnchorKind kind, an::AnchorStatus status)
    {
        return an::ResolvedAnchor{
            .label = "t",
            .kind = kind,
            .status = status,
            .value = 0,
        };
    }

} // namespace dmk_test::anchor_fixture

#endif // DETOURMODKIT_TESTS_FIXTURES_ANCHOR_FIXTURE_HPP
