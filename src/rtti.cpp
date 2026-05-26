/**
 * @file rtti.cpp
 * @brief Implementation of MSVC RTTI introspection primitives.
 *
 * Walks RTTICompleteObjectLocator -> TypeDescriptor -> mangled name through
 * SEH-guarded reads. The COL layout is read in a single batch to minimise the
 * number of guarded-read transitions; on MSVC each __try frame is essentially
 * free, on MinGW each VirtualQuery is microseconds-class so batching matters.
 */

#include "DetourModKit/rtti.hpp"
#include "DetourModKit/memory.hpp"

#include <windows.h>

#include <cstring>

using namespace DetourModKit;

namespace
{
    // MSVC x64 RTTI layout constants. Stable across every Visual C++ release
    // since 2010 and assumed to remain stable; the ABI is not officially
    // documented but is what every disassembler (IDA, Ghidra, Binary Ninja)
    // and every interop tool (MinHook, Detours, EasyHook, SafetyHook) relies
    // on, so DetourModKit treats it as a long-term contract.
    constexpr std::ptrdiff_t COL_OFFSET_FROM_VTABLE = -8;
    constexpr std::ptrdiff_t TD_NAME_OFFSET = 0x10;
    constexpr std::uint32_t COL_SIGNATURE_X64 = 1;
    constexpr std::uintptr_t MIN_VALID_PTR = 0x10000;

    // Page size used to bound name reads so a single SEH read never spans a
    // page boundary; this lets us tolerate a string that ends just before an
    // unmapped page rather than failing the whole read.
    constexpr std::uintptr_t PAGE_MASK = 0xFFF;

    /**
     * @struct ColHead
     * @brief First 24 bytes of an MSVC x64 RTTICompleteObjectLocator.
     * @details Field order is fixed by the MSVC ABI; declaring it as a packed
     *          POD lets resolve_name_site() pull every field in a single SEH
     *          read rather than four separate ones. The struct is trivially
     *          copyable so seh_read<ColHead> instantiates cleanly.
     */
    struct ColHead
    {
        std::uint32_t signature;
        std::uint32_t offset;
        std::uint32_t cd_offset;
        std::uint32_t p_type_descriptor;
        std::uint32_t p_class_descriptor;
        std::uint32_t p_self;
    };
    static_assert(sizeof(ColHead) == 24, "ColHead must match MSVC x64 ABI layout");
    static_assert(std::is_trivially_copyable_v<ColHead>);

    /**
     * @brief Resolves the address of the mangled-name buffer for @p vtable.
     * @return Address of the first byte of the NUL-terminated name, or 0 for
     *         every failure mode (unreadable COL, unrecognised signature,
     *         zero TypeDescriptor RVA, image-base recovery failure).
     */
    std::uintptr_t resolve_name_site(std::uintptr_t vtable) noexcept
    {
        if (vtable < MIN_VALID_PTR)
            return 0;

        // vtable[-1] holds a pointer to the RTTICompleteObjectLocator.
        const auto col_ptr_opt = Memory::seh_read<std::uintptr_t>(
            static_cast<std::uintptr_t>(vtable + COL_OFFSET_FROM_VTABLE));
        if (!col_ptr_opt || *col_ptr_opt < MIN_VALID_PTR)
            return 0;
        const std::uintptr_t col_addr = *col_ptr_opt;

        // Batched read: pulling all six COL fields in one SEH frame matters on
        // MinGW where every guarded read translates into a VirtualQuery.
        const auto head_opt = Memory::seh_read<ColHead>(col_addr);
        if (!head_opt || head_opt->p_type_descriptor == 0)
            return 0;

        // Image-base recovery. On x64 (signature == 1) the COL stores its own
        // RVA in pSelf, which lets the implementation compute the image base
        // without trusting GetModuleHandleExW. This is the canonical approach
        // used by IDA and Ghidra and works for vtables that live in any
        // loaded module.
        std::uintptr_t image_base = 0;
        if (head_opt->signature == COL_SIGNATURE_X64 &&
            head_opt->p_self != 0 &&
            col_addr >= head_opt->p_self)
        {
            image_base = col_addr - head_opt->p_self;
        }

        if (image_base == 0)
        {
            // Fallback path: ask the loader for the vtable's owning module.
            // Required for x86 signature (no pSelf) and for the pathological
            // case of a relocated image whose COL.pSelf would underflow.
            HMODULE mod = nullptr;
            if (!GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(vtable),
                    &mod) ||
                mod == nullptr)
            {
                return 0;
            }
            image_base = reinterpret_cast<std::uintptr_t>(mod);
        }

        return image_base + head_opt->p_type_descriptor + TD_NAME_OFFSET;
    }

    /**
     * @brief Page-bounded NUL-terminated copy from @p addr into @p out.
     * @details Reads in chunks that never cross a 4 KiB page boundary so a
     *          string that ends just before an unmapped page still terminates
     *          cleanly. Returns the number of bytes written (excluding the
     *          NUL terminator the helper appends to @p out).
     */
    std::size_t read_name_seh(std::uintptr_t addr, char *out, std::size_t out_len) noexcept
    {
        if (!out || out_len == 0)
            return 0;
        out[0] = '\0';
        if (addr < MIN_VALID_PTR)
            return 0;

        std::size_t written = 0;
        const std::size_t max_chars = out_len - 1;

        while (written < max_chars)
        {
            const std::uintptr_t cur = addr + written;
            const std::uintptr_t page_end = (cur | PAGE_MASK) + 1;
            const std::size_t to_page_end = static_cast<std::size_t>(page_end - cur);
            const std::size_t remaining = max_chars - written;
            const std::size_t chunk = (to_page_end < remaining) ? to_page_end : remaining;

            char buf[256];
            const std::size_t this_read = (chunk > sizeof(buf)) ? sizeof(buf) : chunk;
            if (!Memory::seh_read_bytes(cur, buf, this_read))
                break;

            const auto *nul = static_cast<const char *>(std::memchr(buf, 0, this_read));
            const std::size_t copy_len = nul ? static_cast<std::size_t>(nul - buf) : this_read;
            std::memcpy(out + written, buf, copy_len);
            written += copy_len;
            if (nul)
                break;
        }

        out[written] = '\0';
        return written;
    }
} // anonymous namespace

std::optional<std::string> Rtti::type_name_of(std::uintptr_t vtable, std::size_t max_len) noexcept
{
    const std::uintptr_t name_addr = resolve_name_site(vtable);
    if (name_addr == 0)
        return std::nullopt;

    if (max_len == 0)
        max_len = DEFAULT_TYPE_NAME_MAX;
    if (max_len > MAX_TYPE_NAME_LEN)
        max_len = MAX_TYPE_NAME_LEN;

    std::string out;
    try
    {
        out.resize(max_len + 1);
    }
    catch (...)
    {
        return std::nullopt;
    }
    const std::size_t len = read_name_seh(name_addr, out.data(), out.size());
    if (len == 0)
        return std::nullopt;
    out.resize(len);
    return out;
}

std::size_t Rtti::type_name_into(std::uintptr_t vtable, char *out, std::size_t out_len) noexcept
{
    if (!out || out_len == 0)
        return 0;
    out[0] = '\0';
    const std::uintptr_t name_addr = resolve_name_site(vtable);
    if (name_addr == 0)
        return 0;
    return read_name_seh(name_addr, out, out_len);
}

bool Rtti::vtable_is_type(std::uintptr_t vtable, std::string_view expected) noexcept
{
    if (expected.empty() || expected.size() >= MAX_TYPE_NAME_LEN)
        return false;

    const std::uintptr_t name_addr = resolve_name_site(vtable);
    if (name_addr == 0)
        return false;

    // Read expected.size() + 1 bytes to capture the terminating NUL. A name
    // that lacks the NUL at expected.size() is either longer (a superstring)
    // or unreadable past that point; both are rejected.
    char buf[MAX_TYPE_NAME_LEN + 1];
    const std::size_t need = expected.size() + 1;
    if (!Memory::seh_read_bytes(name_addr, buf, need))
        return false;
    if (buf[expected.size()] != '\0')
        return false;
    return std::memcmp(buf, expected.data(), expected.size()) == 0;
}

std::optional<std::uintptr_t> Rtti::find_in_pointer_table(
    std::uintptr_t table,
    std::size_t slot_count,
    std::string_view expected,
    std::atomic<std::uintptr_t> *vtable_cache,
    std::size_t stride) noexcept
{
    if (table < MIN_VALID_PTR || slot_count == 0 || expected.empty())
        return std::nullopt;
    if (stride == 0)
        stride = sizeof(std::uintptr_t);

    // Overflow guard on the addressable span. Two failure modes are possible:
    //   1. (slot_count * stride) overflows std::size_t.
    //   2. (table + span) overflows std::uintptr_t.
    // The first check rejects (1) directly; the second catches (2) by
    // comparing the wrapped sum against the base. A malformed (table, stride,
    // slot_count) tuple is treated as an empty table.
    if (slot_count > SIZE_MAX / stride)
        return std::nullopt;
    const std::uintptr_t span = static_cast<std::uintptr_t>(slot_count * stride);
    if (table + span < table)
        return std::nullopt;

    std::uintptr_t cached_vt = 0;
    if (vtable_cache)
        cached_vt = vtable_cache->load(std::memory_order_relaxed);

    for (std::size_t i = 0; i < slot_count; ++i)
    {
        const std::uintptr_t slot_addr = table + i * stride;

        const auto obj_opt = Memory::seh_read<std::uintptr_t>(slot_addr);
        if (!obj_opt || *obj_opt < MIN_VALID_PTR)
            continue;
        const std::uintptr_t obj = *obj_opt;

        const auto vt_opt = Memory::seh_read<std::uintptr_t>(obj);
        if (!vt_opt || *vt_opt < MIN_VALID_PTR)
            continue;
        const std::uintptr_t vt = *vt_opt;

        if (cached_vt != 0)
        {
            if (vt == cached_vt)
                return obj;
            continue;
        }

        if (vtable_is_type(vt, expected))
        {
            if (vtable_cache)
                vtable_cache->store(vt, std::memory_order_relaxed);
            return obj;
        }
    }
    return std::nullopt;
}
