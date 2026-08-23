/**
 * @file rtti_generation_fixture.cpp
 * @brief Fixed-base fixture DLL carrying a hand-laid MSVC x64 RTTI graph inside its own image.
 * @details The graph lives in a writable static buffer so every address the walker follows (vtable, COL, and
 *          TypeDescriptor) resolves back to this module, which is what the walker's in-module bound checks require.
 *          RVAs are computed at prepare time from the running base rather than at link time.
 */

#include "rtti_generation_fixture.hpp"

#include <windows.h>

#include <cstring>

namespace
{
    // Offsets inside the graph buffer, spaced so the COL, TypeDescriptor, pointer table, and vtable never share a
    // cache line and none straddles the buffer end.
    constexpr std::size_t BUFFER_BYTES = 4096;
    constexpr std::size_t COL_OFFSET = 256;
    constexpr std::size_t TD_OFFSET = COL_OFFSET + 24;
    constexpr std::size_t TD_NAME_OFFSET = TD_OFFSET + 16;
    constexpr std::size_t COL_PTR_OFFSET = 2048;
    constexpr std::size_t VTABLE_OFFSET = COL_PTR_OFFSET + 8;
    constexpr std::size_t TABLE_OFFSET = 3072;
    // A stand-in object: its first qword is the vtable pointer, which is what a pointer table's slots address.
    constexpr std::size_t OBJECT_OFFSET = 3584;

    // The name the post-link rewrite patches to produce the second variant. It is a mutable array rather than a string
    // literal so it lands in writable data as one contiguous, uniquely locatable run of bytes.
    char s_type_name[64] = ".?AVDmkRttiGenerationFixtureA@@";

    alignas(16) unsigned char s_graph[BUFFER_BYTES];
    std::uintptr_t s_vtable = 0;

    template <typename T> void write_at(std::size_t offset, const T &value) noexcept
    {
        std::memcpy(s_graph + offset, &value, sizeof(T));
    }
} // namespace

// Each entry point carries its own dllexport. The GNU toolchain auto-exports every symbol when a DLL declares none,
// so omitting them builds a working fixture there and an empty export table under MSVC, where the test would then
// fail for a reason that has nothing to do with what it measures.
extern "C"
{
    __declspec(dllexport) std::uintptr_t dmk_rtti_fixture_prepare(void)
    {
        // Resolve this module by an address inside it rather than by name: both variants ship under different file
        // names, and an address lookup cannot pick the wrong one.
        HMODULE self = nullptr;
        if (GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&s_graph[0]),
                &self
            ) == 0)
        {
            return 0;
        }
        const auto base = reinterpret_cast<std::uintptr_t>(self);
        if (base == 0)
        {
            return 0;
        }

        std::memset(s_graph, 0, sizeof(s_graph));
        const auto buffer_base = reinterpret_cast<std::uintptr_t>(s_graph);
        if (buffer_base < base)
        {
            return 0;
        }
        const std::uintptr_t buffer_rva = buffer_base - base;

        // RTTICompleteObjectLocator, x64 layout: signature 1 carries pSelf, and the walker recomputes the image base
        // as col_addr - pSelf and cross-checks it against the loader's, so pSelf must be exact.
        write_at(COL_OFFSET + 0, std::uint32_t{1});
        write_at(COL_OFFSET + 4, std::uint32_t{0});
        write_at(COL_OFFSET + 8, std::uint32_t{0});
        write_at(COL_OFFSET + 12, static_cast<std::uint32_t>(buffer_rva + TD_OFFSET));
        write_at(COL_OFFSET + 16, std::uint32_t{0});
        write_at(COL_OFFSET + 20, static_cast<std::uint32_t>(buffer_rva + COL_OFFSET));

        // TypeDescriptor: pVFTable, spare, then the NUL-terminated mangled name.
        const std::size_t name_length = std::strlen(s_type_name);
        std::memcpy(s_graph + TD_NAME_OFFSET, s_type_name, name_length);
        s_graph[TD_NAME_OFFSET + name_length] = 0;

        const std::uintptr_t col_address = buffer_base + COL_OFFSET;
        write_at(COL_PTR_OFFSET, col_address);
        s_vtable = buffer_base + VTABLE_OFFSET;

        write_at(OBJECT_OFFSET, s_vtable);
        for (std::size_t slot = 0; slot < dmk_test::RTTI_FIXTURE_TABLE_SLOTS; ++slot)
        {
            const std::uintptr_t value =
                (slot == dmk_test::RTTI_FIXTURE_VTABLE_SLOT) ? (buffer_base + OBJECT_OFFSET) : 0;
            write_at(TABLE_OFFSET + slot * sizeof(std::uintptr_t), value);
        }
        return s_vtable;
    }

    __declspec(dllexport) std::uintptr_t dmk_rtti_fixture_vtable(void)
    {
        return s_vtable;
    }

    __declspec(dllexport) std::uintptr_t dmk_rtti_fixture_table(void)
    {
        return reinterpret_cast<std::uintptr_t>(s_graph) + TABLE_OFFSET;
    }

    __declspec(dllexport) const char *dmk_rtti_fixture_type_name(void)
    {
        return s_type_name;
    }
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}
