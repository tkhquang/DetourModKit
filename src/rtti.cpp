/**
 * @file rtti.cpp
 * @brief Implementation of MSVC RTTI introspection primitives.
 *
 * Walks RTTICompleteObjectLocator -> TypeDescriptor -> mangled name through
 * SEH-guarded reads. The COL layout is read in a single batch to minimise the number of guarded-read transitions; on
 * MSVC each __try frame is essentially free, on MinGW each VirtualQuery is microseconds-class so batching matters.
 *
 * Every address derived from a COL field is bound-checked against the vtable's owning module range before being
 * dereferenced. This guarantees that a forged or corrupted COL cannot redirect the walker to read from another loaded
 * module or from an unrelated mapped region.
 *
 * The verified prelude (resolve_col_site) and the page-bounded name copy (read_name_seh) live in the internal
 * rtti_internal.hpp header so the reverse dissector in rtti_dissect.cpp reuses them byte-for-byte rather than
 * duplicating the walk.
 */

#include "DetourModKit/rtti.hpp"
#include "DetourModKit/memory.hpp"

#include "rtti_internal.hpp"

#include <windows.h>

#include <cstring>

namespace DetourModKit
{
    bool Rtti::detail::resolve_col_site(std::uintptr_t vtable, ColSite &out) noexcept
    {
        if (vtable < MIN_VALID_PTR)
            return false;

        // Anchor every subsequent bound check against the vtable's owning module. Heap pointers and addresses inside
        // unmapped ranges fail here without ever touching memory.
        const auto mod_range_opt = Memory::module_range_for(reinterpret_cast<const void *>(vtable));
        if (!mod_range_opt)
            return false;
        const auto mod_range = *mod_range_opt;

        // vtable[-1] holds a pointer to the RTTICompleteObjectLocator. The COL must live in the same module as the
        // vtable; a COL pointer escaping the module range is the signature of a forged or relocated structure and
        // aborts the walk.
        const auto col_ptr_opt =
            Memory::seh_read<std::uintptr_t>(static_cast<std::uintptr_t>(vtable + COL_OFFSET_FROM_VTABLE));
        if (!col_ptr_opt || !Memory::contains(mod_range, *col_ptr_opt))
            return false;
        const std::uintptr_t col_addr = *col_ptr_opt;

        // contains() above proved col_addr is in [base, end), but the seh_read<ColHead> below pulls sizeof(ColHead)
        // bytes, which a COL sitting within that many bytes of the module end would straddle past. The SEH guard
        // faults cleanly on an unmapped straddle, but reject the whole-span overrun up front so the walk never reads
        // COL fields out of an adjacent mapped image. (mod_range.end - col_addr cannot underflow: col_addr < end.)
        if (mod_range.end - col_addr < sizeof(ColHead))
            return false;

        // Batched read: pulling all six COL fields in one SEH frame matters on
        // MinGW where every guarded read translates into a VirtualQuery.
        const auto head_opt = Memory::seh_read<ColHead>(col_addr);
        if (!head_opt || head_opt->p_type_descriptor == 0)
            return false;

        // Scope is x64 MSVC, where the COL signature is always 1 and carries pSelf, an RVA back to the COL itself.
        // Reject any other signature
        // outright: a non-x64 or corrupt signature has no pSelf to cross-check,
        // so accepting it would skip the forgery guard below and fall through to the loader base unverified. The
        // canonical IDA/Ghidra technique computes the image base as col_addr - p_self; cross-check that recovered base
        // against the loader-reported module base so a forged p_self cannot bend the walk to another module.
        if (head_opt->signature != COL_SIGNATURE_X64)
            return false;
        if (head_opt->p_self == 0 || col_addr < head_opt->p_self)
            return false;
        if (col_addr - head_opt->p_self != mod_range.base)
            return false;

        // Compute the TypeDescriptor and name-buffer addresses from the module base plus the type-descriptor RVA. A
        // bogus RVA that places the name buffer outside the module range (or wraps the address space) is rejected by
        // Memory::contains, which also requires the range to be valid. The name address is the strictly-higher of the
        // two (td + 0x10), so bound-checking it implies td_addr is in range as well.
        const std::uintptr_t td_addr = mod_range.base + head_opt->p_type_descriptor;
        const std::uintptr_t name_addr = td_addr + TD_NAME_OFFSET;
        if (!Memory::contains(mod_range, name_addr))
            return false;

        out.col_addr = col_addr;
        out.td_addr = td_addr;
        out.name_addr = name_addr;
        out.col_offset = head_opt->offset;
        return true;
    }

    std::size_t Rtti::detail::read_name_seh(std::uintptr_t addr, char *out, std::size_t out_len) noexcept
    {
        if (!out || out_len == 0)
            return 0;
        out[0] = '\0';
        if (addr < MIN_VALID_PTR)
            return 0;

        const std::size_t max_chars = out_len - 1;

        // The temporary is capped at Rtti::MAX_TYPE_NAME_LEN, which is the documented hard upper bound for any single
        // name read. Names produced by MSVC RTTI in practice never approach this bound, so the cap costs nothing.
        char tmp[MAX_TYPE_NAME_LEN];
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

        // Commit only when either a NUL was found or the buffer was filled to accum_cap without faulting. A read fault
        // before either condition is reported as a clean failure: the caller-visible buffer stays empty and the return
        // is zero.
        if (read_failed && !found_nul)
        {
            out[0] = '\0';
            return 0;
        }

        std::memcpy(out, tmp, written);
        out[written] = '\0';
        return written;
    }

    namespace
    {
        /**
         * @brief Resolves the address of the mangled-name buffer for @p vtable.
         * @details Thin wrapper over Rtti::detail::resolve_col_site that keeps the forward walker's "name address or
         *          zero" contract. Every failure mode of the prelude collapses to a 0 return.
         * @return Address of the first byte of the NUL-terminated name, or 0 on any failure.
         */
        std::uintptr_t resolve_name_site(std::uintptr_t vtable) noexcept
        {
            Rtti::detail::ColSite site;
            return Rtti::detail::resolve_col_site(vtable, site) ? site.name_addr : 0;
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
        const std::size_t len = detail::read_name_seh(name_addr, out.data(), out.size());
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
        return detail::read_name_seh(name_addr, out, out_len);
    }

    bool Rtti::vtable_is_type(std::uintptr_t vtable, std::string_view expected) noexcept
    {
        if (expected.empty() || expected.size() >= MAX_TYPE_NAME_LEN)
            return false;

        const std::uintptr_t name_addr = resolve_name_site(vtable);
        if (name_addr == 0)
            return false;

        // Read expected.size() + 1 bytes to capture the terminating NUL. A name that lacks the NUL at expected.size()
        // is either longer (a superstring) or unreadable past that point; both are rejected.
        char buf[MAX_TYPE_NAME_LEN + 1];
        const std::size_t need = expected.size() + 1;
        if (!Memory::seh_read_bytes(name_addr, buf, need))
            return false;
        if (buf[expected.size()] != '\0')
            return false;
        return std::memcmp(buf, expected.data(), expected.size()) == 0;
    }

    std::optional<std::uintptr_t> Rtti::find_in_pointer_table(std::uintptr_t table, std::size_t slot_count,
                                                              std::string_view expected,
                                                              std::atomic<std::uintptr_t> *vtable_cache,
                                                              std::size_t stride) noexcept
    {
        if (table < detail::MIN_VALID_PTR || slot_count == 0 || expected.empty())
            return std::nullopt;
        if (stride == 0)
            stride = sizeof(std::uintptr_t);

        // Overflow guard on the addressable span. Two failure modes are
        // possible:
        //   1. (slot_count * stride) overflows std::size_t.
        //   2. (table + span) overflows std::uintptr_t.
        // The first check rejects (1) directly; the second catches (2) by comparing the wrapped sum against the base. A
        // malformed (table, stride, slot_count) tuple is treated as an empty table.
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
            if (!obj_opt || *obj_opt < detail::MIN_VALID_PTR)
                continue;
            const std::uintptr_t obj = *obj_opt;

            const auto vt_opt = Memory::seh_read<std::uintptr_t>(obj);
            if (!vt_opt || *vt_opt < detail::MIN_VALID_PTR)
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

    namespace
    {
        // Upper bound on distinct sub-object vtables collected for one mangled name. Multiple/virtual inheritance
        // produces a handful at most; the cap keeps the reverse scan allocation-free (matches live in a stack array)
        // and bounds a pathological duplicate-type image.
        inline constexpr std::size_t MAX_REVERSE_MATCHES = 64;

        // One readable, non-executable image-resident scan window.
        struct ScanRange
        {
            std::uintptr_t begin = 0;
            std::uintptr_t end = 0;
        };

        // A validated reverse-RTTI hit: the vtable and the COL.offset of the sub-object it belongs to (0 ==
        // primary/most-derived).
        struct VtMatch
        {
            std::uintptr_t vtable = 0;
            std::uint32_t col_offset = 0;
        };

        /**
         * @brief Enumerates the module's readable, non-executable, non-discardable sections -- where MSVC keeps vtables
         *        and their
         *        RTTI meta-pointers (.rdata for a normal /GR image, .data for a packed or section-merged one).
         * @details .text is skipped on purpose: a vtable's [-1] COL meta-slot never lives in executable code, and
         *          sweeping code pages qword-by-qword would multiply the one-time cost for nothing. Every header field
         *          is bound- and signature-checked so a malformed or hostile image fails closed instead of being read
         *          through.
         * @return The number of ranges written into @p out; 0 means the PE headers could not be parsed and the caller
         *         falls back to the whole module image.
         */
        std::size_t collect_rtti_scan_ranges(Memory::ModuleRange mod, ScanRange *out, std::size_t cap) noexcept
        {
            const auto dos = Memory::seh_read<IMAGE_DOS_HEADER>(mod.base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
                return 0;

            const std::uintptr_t nt_addr =
                mod.base + static_cast<std::uintptr_t>(static_cast<std::uint32_t>(dos->e_lfanew));
            // The NT headers must lie inside the image; a wild e_lfanew is the signature of a forged or truncated
            // header.
            if (!Memory::contains(mod, nt_addr) || !Memory::contains(mod, nt_addr + sizeof(IMAGE_NT_HEADERS64)))
                return 0;

            const auto nt = Memory::seh_read<IMAGE_NT_HEADERS64>(nt_addr);
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return 0;

            // The Windows loader caps a PE at 96 sections; a larger count is corrupt and would otherwise let the loop
            // below run away.
            const std::uint32_t num_sections = nt->FileHeader.NumberOfSections;
            if (num_sections == 0 || num_sections > 96)
                return 0;

            // IMAGE_FIRST_SECTION: the section table starts immediately after the
            // optional header, whose length is SizeOfOptionalHeader. Using sizeof(IMAGE_NT_HEADERS64) instead would
            // misplace the table whenever the optional-header size differs from the compile-time struct size.
            const std::uintptr_t sec_table =
                nt_addr + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;

            std::size_t count = 0;
            for (std::uint32_t i = 0; i < num_sections && count < cap; ++i)
            {
                const std::uintptr_t hdr_addr =
                    sec_table + static_cast<std::uintptr_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                if (!Memory::contains(mod, hdr_addr + sizeof(IMAGE_SECTION_HEADER)))
                    break;

                const auto sec = Memory::seh_read<IMAGE_SECTION_HEADER>(hdr_addr);
                if (!sec)
                    break;

                const std::uint32_t ch = sec->Characteristics;
                const bool readable = (ch & IMAGE_SCN_MEM_READ) != 0;
                const bool executable = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
                const bool discardable = (ch & IMAGE_SCN_MEM_DISCARDABLE) != 0;
                if (!readable || executable || discardable)
                    continue;

                // Use the in-memory extent (VirtualAddress + VirtualSize), never the on-disk
                // PointerToRawData/SizeOfRawData: those are file offsets and do not survive section alignment once
                // mapped.
                const std::uintptr_t begin = mod.base + sec->VirtualAddress;
                const std::uintptr_t end = begin + sec->Misc.VirtualSize;
                if (end <= begin || !Memory::contains(mod, begin) || end > mod.end)
                    continue;

                out[count].begin = begin;
                out[count].end = end;
                ++count;
            }
            return count;
        }

        /**
         * @brief Byte-exact comparison of the NUL-terminated name at @p name_addr with @p mangled, including the
         *        terminator so a superstring does not match.
         * @details Mirrors vtable_is_type's name check; the caller guarantees mangled.size() < MAX_TYPE_NAME_LEN.
         */
        [[nodiscard]] bool name_equals(std::uintptr_t name_addr, std::string_view mangled) noexcept
        {
            char buf[Rtti::MAX_TYPE_NAME_LEN + 1];
            const std::size_t need = mangled.size() + 1;
            if (!Memory::seh_read_bytes(name_addr, buf, need))
                return false;
            if (buf[mangled.size()] != '\0')
                return false;
            return std::memcmp(buf, mangled.data(), mangled.size()) == 0;
        }

        /**
         * @brief Sweeps one [begin,end) window for vtables whose RTTI name equals @p mangled, appending validated,
         *        deduped matches to @p out (capped at @p cap).
         * @details The window is read in page-bounded chunks (one guarded read per page) and scanned in-process, so the
         *          guarded-read count is per-page rather than per-qword -- the difference between a few hundred and a
         *          few hundred thousand guarded transitions over a multi-megabyte section. A meta-slot is a qword that
         *          points to an in-module COL; the vtable that owns it is slot + 8, validated by the same COL prelude
         *          the forward walker uses, so the in-range pre-filter only spares a deeper read and never decides
         *          correctness.
         */
        void sweep_range_for_name(Memory::ModuleRange mod, std::uintptr_t begin, std::uintptr_t end,
                                  std::string_view mangled, VtMatch *out, std::size_t cap, std::size_t &count) noexcept
        {
            // Image-resident pointer storage is 8-byte aligned, so only qword-aligned slots can hold a vtable
            // meta-pointer.
            std::uintptr_t addr = (begin + 7) & ~static_cast<std::uintptr_t>(7);

            while (addr + sizeof(std::uintptr_t) <= end && count < cap)
            {
                // Never let one guarded read cross a page boundary: an unmapped page then fails only its own chunk, not
                // the whole window.
                const std::uintptr_t page_end = (addr | Rtti::detail::PAGE_MASK) + 1;
                const std::uintptr_t chunk_end = (page_end < end) ? page_end : end;
                const std::size_t qwords = static_cast<std::size_t>(chunk_end - addr) / sizeof(std::uintptr_t);
                if (qwords == 0)
                {
                    addr = chunk_end;
                    continue;
                }

                // a 4 KiB page holds at most 512 qwords
                std::uintptr_t buf[512];
                const std::size_t want = (qwords < 512) ? qwords : 512;
                if (Memory::seh_read_bytes(addr, buf, want * sizeof(std::uintptr_t)))
                {
                    for (std::size_t j = 0; j < want && count < cap; ++j)
                    {
                        // Pre-filter: a meta-slot holds a pointer to a COL inside
                        // this module. Most qwords fail here without a second read.
                        if (!Memory::contains(mod, buf[j]))
                            continue;

                        const std::uintptr_t slot_addr = addr + j * sizeof(std::uintptr_t);
                        const std::uintptr_t candidate_vtable = slot_addr + sizeof(std::uintptr_t);

                        Rtti::detail::ColSite site;
                        if (!Rtti::detail::resolve_col_site(candidate_vtable, site))
                            continue;
                        if (!name_equals(site.name_addr, mangled))
                            continue;

                        bool seen = false;
                        for (std::size_t k = 0; k < count; ++k)
                        {
                            if (out[k].vtable == candidate_vtable)
                            {
                                seen = true;
                                break;
                            }
                        }
                        if (!seen)
                        {
                            out[count].vtable = candidate_vtable;
                            out[count].col_offset = site.col_offset;
                            ++count;
                        }
                    }
                }

                addr += want * sizeof(std::uintptr_t);
            }
        }

        /**
         * @brief Finds vtables for @p mangled across the module's RTTI-bearing sections, returning the count written
         *        into @p out (deduped, capped at @p cap).
         * @details Sweeps the readable non-executable sections; if the PE headers cannot be parsed, falls back to the
         *          whole module image rather than reporting a confident-but-wrong "not found" for a packed or merged
         *          binary.
         */
        std::size_t scan_vtables_for_name(Memory::ModuleRange mod, std::string_view mangled, VtMatch *out,
                                          std::size_t cap) noexcept
        {
            if (!mod.valid() || mangled.empty() || mangled.size() >= Rtti::MAX_TYPE_NAME_LEN)
                return 0;

            ScanRange ranges[32];
            const std::size_t range_count = collect_rtti_scan_ranges(mod, ranges, 32);

            std::size_t count = 0;
            if (range_count == 0)
            {
                // No usable scan window (the PE headers could not be parsed, or no readable non-executable section
                // qualified): sweep the whole image rather than report a confident-but-wrong "not found" for a packed
                // or section-merged binary. The whole-image sweep is a strict superset, and resolve_col_site still
                // validates every candidate.
                sweep_range_for_name(mod, mod.base, mod.end, mangled, out, cap, count);
                return count;
            }

            for (std::size_t i = 0; i < range_count && count < cap; ++i)
            {
                sweep_range_for_name(mod, ranges[i].begin, ranges[i].end, mangled, out, cap, count);
            }
            return count;
        }
    } // anonymous namespace

    std::optional<std::uintptr_t> Rtti::vtable_for_type(std::string_view mangled, Memory::ModuleRange range) noexcept
    {
        VtMatch matches[MAX_REVERSE_MATCHES];
        const std::size_t match_count = scan_vtables_for_name(range, mangled, matches, MAX_REVERSE_MATCHES);

        // The primary vtable is the COL.offset == 0 sub-object: the value an object pointer's first qword holds for a
        // most-derived instance, i.e. the faithful inverse of vtable_is_type. More than one distinct primary for the
        // same name (a type linked into the image twice) is ambiguous; fail closed rather than return an arbitrary one.
        std::optional<std::uintptr_t> primary;
        for (std::size_t i = 0; i < match_count; ++i)
        {
            if (matches[i].col_offset != 0)
                continue;
            if (primary && *primary != matches[i].vtable)
                return std::nullopt;
            primary = matches[i].vtable;
        }

        // scan_vtables_for_name saturated its match buffer (match_count reached the cap), so vtables for this name may
        // exist beyond MAX_REVERSE_MATCHES that the loop above never inspected -- including a second distinct primary
        // that would make the result ambiguous. The uniqueness guarantee cannot hold across a truncated scan, so fail
        // closed rather than hand back a primary that might not be the only one. A name with this many sub-object
        // vtables is already a pathological / ODR-duplicated image; the documented happy case is a handful.
        if (match_count == MAX_REVERSE_MATCHES && primary)
            return std::nullopt;

        return primary;
    }

    std::size_t Rtti::vtables_for_type(std::string_view mangled, std::uintptr_t *out, std::size_t out_cap,
                                       Memory::ModuleRange range) noexcept
    {
        if (!out)
            out_cap = 0;

        VtMatch matches[MAX_REVERSE_MATCHES];
        const std::size_t match_count = scan_vtables_for_name(range, mangled, matches, MAX_REVERSE_MATCHES);

        // Ascending COL.offset so the primary (offset 0) sorts first. The match count is tiny (one per base
        // sub-object), so an in-place insertion sort is both adequate and allocation-free.
        for (std::size_t i = 1; i < match_count; ++i)
        {
            const VtMatch key = matches[i];
            std::size_t sorted = i;
            while (sorted > 0 && matches[sorted - 1].col_offset > key.col_offset)
            {
                matches[sorted] = matches[sorted - 1];
                --sorted;
            }
            matches[sorted] = key;
        }

        const std::size_t to_write = (match_count < out_cap) ? match_count : out_cap;
        for (std::size_t i = 0; i < to_write; ++i)
            out[i] = matches[i].vtable;
        return match_count;
    }

    Rtti::TypeIdentity::TypeIdentity(std::string_view mangled, Memory::ModuleRange range) noexcept
        : m_mangled(mangled), m_range(range)
    {
    }

    std::optional<std::uintptr_t> Rtti::TypeIdentity::vtable() const noexcept
    {
        // Fast path: a completed resolve stored m_cached before publishing m_resolved with release, so an acquire-load
        // that sees m_resolved also sees the cached value.
        if (m_resolved.load(std::memory_order_acquire))
        {
            const std::uintptr_t cached = m_cached.load(std::memory_order_relaxed);
            return cached != 0 ? std::optional<std::uintptr_t>(cached) : std::nullopt;
        }

        // First use: resolve and cache. Concurrent first-callers converge on the same vtable, so a benign
        // double-resolve needs no lock.
        const auto resolved = vtable_for_type(m_mangled, m_range);
        m_cached.store(resolved.value_or(0), std::memory_order_relaxed);
        m_resolved.store(true, std::memory_order_release);
        return resolved;
    }

    bool Rtti::TypeIdentity::matches(std::uintptr_t vtable) const noexcept
    {
        const auto resolved = TypeIdentity::vtable();
        return resolved.has_value() && *resolved == vtable;
    }
} // namespace DetourModKit
