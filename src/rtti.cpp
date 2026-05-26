/**
 * @file rtti.cpp
 * @brief Implementation of MSVC RTTI introspection primitives.
 *
 * Walks RTTICompleteObjectLocator -> TypeDescriptor -> mangled name through
 * SEH-guarded reads. The COL layout is read in a single batch to minimise the
 * number of guarded-read transitions; on MSVC each __try frame is essentially
 * free, on MinGW each VirtualQuery is microseconds-class so batching matters.
 *
 * Every address derived from a COL field is bound-checked against the vtable's
 * owning module range before being dereferenced. This guarantees that a
 * forged or corrupted COL cannot redirect the walker to read from another
 * loaded module or from an unrelated mapped region.
 */

#include "DetourModKit/rtti.hpp"
#include "DetourModKit/memory.hpp"

#include <windows.h>

#include <cstring>

namespace DetourModKit
{
    namespace
    {
        // MSVC x64 RTTI layout constants. Stable across every Visual C++
        // release since 2010 and assumed to remain stable; the ABI is not
        // officially documented but is what every disassembler (IDA, Ghidra,
        // Binary Ninja) and every interop tool (MinHook, Detours, EasyHook,
        // SafetyHook) relies on, so DetourModKit treats it as a long-term
        // contract.
        constexpr std::ptrdiff_t COL_OFFSET_FROM_VTABLE = -8;
        constexpr std::ptrdiff_t TD_NAME_OFFSET = 0x10;
        constexpr std::uint32_t COL_SIGNATURE_X64 = 1;
        constexpr std::uintptr_t MIN_VALID_PTR = 0x10000;

        // Page size used to bound name reads so a single SEH read never spans
        // a page boundary; this lets the walker tolerate a string that ends
        // just before an unmapped page rather than failing the whole read.
        constexpr std::uintptr_t PAGE_MASK = 0xFFF;

        /**
         * @struct ColHead
         * @brief First 24 bytes of an MSVC x64 RTTICompleteObjectLocator.
         * @details Field order is fixed by the MSVC ABI; declaring it as a
         *          packed POD lets resolve_name_site() pull every field in
         *          a single SEH read rather than four separate ones. The
         *          struct is trivially copyable so seh_read<ColHead>
         *          instantiates cleanly.
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
         * @details Every intermediate address (the COL pointer, the
         *          pSelf-recovered image base, and the final name buffer) is
         *          required to lie inside the vtable's owning module range.
         *          This forces a poisoned COL to fail closed: a forged
         *          p_type_descriptor that would otherwise redirect the read
         *          to another loaded module or to unmapped memory is
         *          rejected here instead of read-through.
         * @return Address of the first byte of the NUL-terminated name, or
         *         0 for every failure mode (vtable not in a loaded module,
         *         unreadable COL, COL pointer escaping the module range,
         *         pSelf disagreeing with the loader-reported module base,
         *         zero TypeDescriptor RVA, computed name address escaping
         *         the module range).
         */
        std::uintptr_t resolve_name_site(std::uintptr_t vtable) noexcept
        {
            if (vtable < MIN_VALID_PTR)
                return 0;

            // Anchor every subsequent bound check against the vtable's
            // owning module. Heap pointers and addresses inside unmapped
            // ranges fail here without ever touching memory.
            const auto mod_range_opt = Memory::module_range_for(
                reinterpret_cast<const void *>(vtable));
            if (!mod_range_opt)
                return 0;
            const auto mod_range = *mod_range_opt;

            // vtable[-1] holds a pointer to the RTTICompleteObjectLocator.
            // The COL must live in the same module as the vtable; a COL
            // pointer escaping the module range is the signature of a
            // forged or relocated structure and aborts the walk.
            const auto col_ptr_opt = Memory::seh_read<std::uintptr_t>(
                static_cast<std::uintptr_t>(vtable + COL_OFFSET_FROM_VTABLE));
            if (!col_ptr_opt || !Memory::contains(mod_range, *col_ptr_opt))
                return 0;
            const std::uintptr_t col_addr = *col_ptr_opt;

            // Batched read: pulling all six COL fields in one SEH frame
            // matters on MinGW where every guarded read translates into a
            // VirtualQuery.
            const auto head_opt = Memory::seh_read<ColHead>(col_addr);
            if (!head_opt || head_opt->p_type_descriptor == 0)
                return 0;

            // x64 (signature == 1) carries pSelf, an RVA back to the COL
            // itself. The canonical IDA/Ghidra technique computes the
            // image base as col_addr - p_self and uses that base for every
            // subsequent RVA resolution. Cross-check the recovered base
            // against the loader-reported module base so a forged p_self
            // cannot bend the walk elsewhere. The x86 signature has no
            // pSelf field; in that case the loader-reported module base
            // is used directly because there is nothing to cross-check
            // against.
            if (head_opt->signature == COL_SIGNATURE_X64)
            {
                if (head_opt->p_self == 0 || col_addr < head_opt->p_self)
                    return 0;
                if (col_addr - head_opt->p_self != mod_range.base)
                    return 0;
            }

            // Compute the name-buffer address from the module base plus the
            // type-descriptor RVA. A bogus RVA that places the name buffer
            // outside the module range (or wraps the address space) is
            // rejected by Memory::contains, which also requires the range
            // to be valid.
            const std::uintptr_t name_addr =
                mod_range.base + head_opt->p_type_descriptor + TD_NAME_OFFSET;
            if (!Memory::contains(mod_range, name_addr))
                return 0;
            return name_addr;
        }

        /**
         * @brief Page-bounded NUL-terminated copy from @p addr into @p out.
         * @details Reads in chunks that never cross a 4 KiB page boundary so
         *          a string that ends just before an unmapped page still
         *          terminates cleanly. To honour the all-or-nothing failure
         *          contract, bytes are first accumulated in a local
         *          temporary; the final commit into @p out only happens
         *          when either the terminating NUL is observed or the
         *          allowed length is filled in full. A read fault before
         *          either condition leaves @p out as the empty NUL-
         *          terminated string and returns 0.
         * @return Number of bytes written excluding the NUL terminator, or
         *         0 on any partial-read failure.
         */
        std::size_t read_name_seh(std::uintptr_t addr, char *out, std::size_t out_len) noexcept
        {
            if (!out || out_len == 0)
                return 0;
            out[0] = '\0';
            if (addr < MIN_VALID_PTR)
                return 0;

            const std::size_t max_chars = out_len - 1;

            // The temporary is capped at Rtti::MAX_TYPE_NAME_LEN, which is
            // the documented hard upper bound for any single name read.
            // Names produced by MSVC RTTI in practice never approach this
            // bound, so the cap costs nothing.
            char tmp[Rtti::MAX_TYPE_NAME_LEN];
            const std::size_t accum_cap = (max_chars < sizeof(tmp)) ? max_chars : sizeof(tmp);

            std::size_t written = 0;
            bool found_nul = false;
            bool read_failed = false;

            while (written < accum_cap)
            {
                const std::uintptr_t cur = addr + written;
                const std::uintptr_t page_end = (cur | PAGE_MASK) + 1;
                const std::size_t to_page_end = static_cast<std::size_t>(page_end - cur);
                const std::size_t remaining = accum_cap - written;
                const std::size_t chunk = (to_page_end < remaining) ? to_page_end : remaining;

                char buf[256];
                const std::size_t this_read = (chunk > sizeof(buf)) ? sizeof(buf) : chunk;
                if (!Memory::seh_read_bytes(cur, buf, this_read))
                {
                    read_failed = true;
                    break;
                }

                const auto *nul = static_cast<const char *>(std::memchr(buf, 0, this_read));
                const std::size_t copy_len = nul ? static_cast<std::size_t>(nul - buf) : this_read;
                std::memcpy(tmp + written, buf, copy_len);
                written += copy_len;
                if (nul)
                {
                    found_nul = true;
                    break;
                }
            }

            // Commit only when either a NUL was found or the buffer was
            // filled to accum_cap without faulting. A read fault before
            // either condition is reported as a clean failure: the
            // caller-visible buffer stays empty and the return is zero.
            if (read_failed && !found_nul)
            {
                out[0] = '\0';
                return 0;
            }

            std::memcpy(out, tmp, written);
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

        // Read expected.size() + 1 bytes to capture the terminating NUL. A
        // name that lacks the NUL at expected.size() is either longer (a
        // superstring) or unreadable past that point; both are rejected.
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

        // Overflow guard on the addressable span. Two failure modes are
        // possible:
        //   1. (slot_count * stride) overflows std::size_t.
        //   2. (table + span) overflows std::uintptr_t.
        // The first check rejects (1) directly; the second catches (2) by
        // comparing the wrapped sum against the base. A malformed
        // (table, stride, slot_count) tuple is treated as an empty table.
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
} // namespace DetourModKit
