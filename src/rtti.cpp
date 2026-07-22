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
 * rtti_shared.hpp header so the reverse dissector in rtti_dissect.cpp reuses them byte-for-byte rather than
 * duplicating the walk.
 *
 * The public surface uses Address; the raw ABI sweepers below stay on std::uintptr_t because they do qword-granular
 * pointer arithmetic over image memory, and the Address <-> integer punning is confined to the boundary conversions at
 * each public entry point.
 */

#include "DetourModKit/rtti.hpp"
#include "DetourModKit/memory.hpp"

#include "internal/memory_guarded.hpp"
#include "internal/memory_representation_win32.hpp"
#include "internal/rtti_shared.hpp"

#include <windows.h>

#include <cstdint>
#include <cstring>

namespace DetourModKit::detail
{
    template <> struct enable_representation_safe_aggregate<rtti::detail::ColHead> : std::true_type
    {
    };
} // namespace DetourModKit::detail

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    // Test-only override for the monotonic millisecond clock TypeIdentity's unresolved re-sweep throttle reads. Null in
    // test builds unless a fixture installs a controllable source.
    std::uint64_t (*g_rtti_resolve_clock_override)() noexcept = nullptr;

    // Test-only controls for mapping-generation and module-extent transitions.
    std::uint64_t (*g_rtti_image_generation_override)(std::uintptr_t address) noexcept = nullptr;
    Region (*g_rtti_module_region_override)(Address address) noexcept = nullptr;
#endif
} // namespace DetourModKit::detail

namespace DetourModKit
{
    namespace
    {
        // Monotonic millisecond clock for the TypeIdentity re-sweep throttle. GetTickCount64 reads KUSER_SHARED_DATA
        // (no syscall), so gating the per-frame miss path on it is essentially free. Routed through the test override
        // so the suite can advance time deterministically without a real sleep.
        [[nodiscard]] std::uint64_t rtti_now_ms() noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *override_fn = DetourModKit::detail::g_rtti_resolve_clock_override)
            {
                return override_fn();
            }
#endif
            return ::GetTickCount64();
        }

        // After an unresolved TypeIdentity miss, skip re-sweeping the whole module until this many milliseconds have
        // elapsed. A miss is never latched permanently (the owning module may map the type later -- a DLL loads, or a
        // patch finishes relocating the vtable), so without a throttle a per-frame identity check for an absent type
        // would re-sweep the entire module every frame, the one genuine per-frame cliff. 250 ms bounds that to at most
        // ~4 module sweeps per second while keeping the eventual resolve latency sub-second once the type appears.
        constexpr std::uint64_t RESOLVE_RETRY_COOLDOWN_MS = 250;

        // Complete < Incomplete < Saturated, so the maximum retains the strongest reason a verdict is not
        // authoritative.
        [[nodiscard]] rtti::Traversal merge_traversal(rtti::Traversal a, rtti::Traversal b) noexcept
        {
            return (static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b)) ? b : a;
        }

        [[nodiscard]] Region current_module_region(Address address) noexcept;
        [[nodiscard]] std::uint64_t current_image_stamp(std::uintptr_t module_base) noexcept;
    } // namespace

    bool rtti::detail::resolve_col_site(std::uintptr_t vtable, const DetourModKit::detail::ModuleSpan &mod_range,
                                        ColSite &out) noexcept
    {
        if (vtable < MIN_VALID_PTR)
            return false;

        // The caller supplies the vtable's owning-module span, so this overload skips the per-candidate
        // memory::module_of loader lookup. Require the vtable to lie inside the supplied span so every bound check
        // below anchors on the module that actually owns it -- the invariant the module_of-resolving overload gets
        // implicitly (the loader only resolves a module that contains the address). A candidate one past the module
        // end fails closed here rather than validating against a foreign module.
        if (!mod_range.valid() || !mod_range.contains(vtable))
            return false;

        // vtable[-1] holds a pointer to the RTTICompleteObjectLocator. The COL must live in the same module as the
        // vtable; a COL pointer escaping the module range is the signature of a forged or relocated structure and
        // aborts the walk.
        const auto col_ptr_opt = DetourModKit::detail::guarded_read<std::uintptr_t>(
            static_cast<std::uintptr_t>(vtable + COL_OFFSET_FROM_VTABLE));
        if (!col_ptr_opt || !mod_range.contains(*col_ptr_opt))
            return false;
        const std::uintptr_t col_addr = *col_ptr_opt;

        // contains() above proved col_addr is in [base, end), but the guarded_read<ColHead> below pulls sizeof(ColHead)
        // bytes, which a COL sitting within that many bytes of the module end would straddle past. The SEH guard
        // faults cleanly on an unmapped straddle, but reject the whole-span overrun up front so the walk never reads
        // COL fields out of an adjacent mapped image. (mod_range.end - col_addr cannot underflow: col_addr < end.)
        if (mod_range.end - col_addr < sizeof(ColHead))
            return false;

        // Batched read: pulling all six COL fields in one SEH frame matters on
        // MinGW where every guarded read translates into a VirtualQuery.
        const auto head_opt = DetourModKit::detail::guarded_read<ColHead>(col_addr);
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
        // the in-module bound check, which also requires the range to be valid. The name address is the strictly-higher
        // of the two (td + 0x10), so bound-checking it implies td_addr is in range as well.
        const std::uintptr_t td_addr = mod_range.base + head_opt->p_type_descriptor;
        const std::uintptr_t name_addr = td_addr + TD_NAME_OFFSET;
        if (!mod_range.contains(name_addr))
            return false;

        out.col_addr = col_addr;
        out.td_addr = td_addr;
        out.name_addr = name_addr;
        // Carry the owning module's end so read_name_seh can clamp the name copy to this module: name_addr is proven
        // below module_end (contains() above), but the string past it is not, so the read must stop at the boundary.
        out.module_end = mod_range.end;
        out.col_offset = head_opt->offset;
        return true;
    }

    bool rtti::detail::resolve_col_site(std::uintptr_t vtable, ColSite &out) noexcept
    {
        // Reject obviously-invalid pointers before the loader lookup so a heap or tiny address never pays for a
        // GetModuleHandleExW that would only fail. A valid vtable resolves its owning module, then the shared walk runs
        // through the span overload; an unmapped or unowned address yields an invalid span the overload rejects.
        if (vtable < MIN_VALID_PTR)
            return false;
        const DetourModKit::detail::ModuleSpan mod_range =
            DetourModKit::detail::module_span(DetourModKit::detail::live_module_region(Address{vtable}));
        return resolve_col_site(vtable, mod_range, out);
    }

    std::size_t rtti::detail::read_name_seh(std::uintptr_t addr, char *out, std::size_t out_len,
                                            std::uintptr_t module_end) noexcept
    {
        if (!out || out_len == 0)
            return 0;
        out[0] = '\0';
        if (addr < MIN_VALID_PTR)
            return 0;

        const std::size_t max_chars = out_len - 1;

        // The temporary is capped at rtti::MAX_TYPE_NAME_LEN, which is the documented hard upper bound for any single
        // name read. Names produced by MSVC RTTI in practice never approach this bound, so the cap costs nothing.
        char tmp[MAX_TYPE_NAME_LEN];
        std::size_t accum_cap = (max_chars < sizeof(tmp)) ? max_chars : sizeof(tmp);

        // Clamp the accumulation to the owning module's end. resolve_col_site proves name_addr < module_end, so the
        // in-module span is at least one byte; capping accum_cap at (module_end - addr) stops a name with no NUL before
        // the module boundary from reading forward into an adjacent mapped image and returning another module's bytes
        // as a confident name. A zero module_end means no bound was supplied (only the length caps apply).
        if (module_end != 0)
        {
            if (module_end <= addr)
                return 0;
            const std::size_t to_module_end = static_cast<std::size_t>(module_end - addr);
            if (to_module_end < accum_cap)
                accum_cap = to_module_end;
        }

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
            if (!DetourModKit::detail::guarded_read_bytes(cur, buf, this_read))
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
         * @brief Resolves the address of the mangled-name buffer for @p vtable, plus its owning-module end.
         * @details Thin wrapper over rtti::detail::resolve_col_site that keeps the forward walker's "name address or
         *          zero" contract. Every failure mode of the prelude collapses to a 0 return. @p module_end_out
         *          receives the owning module's exclusive end so the caller's name read can clamp to the module (the
         *          RTTI-name over-read guard); it is left untouched on a 0 return.
         * @return Address of the first byte of the NUL-terminated name, or 0 on any failure.
         */
        std::uintptr_t resolve_name_site(std::uintptr_t vtable, std::uintptr_t &module_end_out) noexcept
        {
            rtti::detail::ColSite site;
            if (!rtti::detail::resolve_col_site(vtable, site))
                return 0;
            module_end_out = site.module_end;
            return site.name_addr;
        }
    } // anonymous namespace

    std::optional<std::string> rtti::type_name_of(Address vtable, std::size_t max_len) noexcept
    {
        std::uintptr_t module_end = 0;
        const std::uintptr_t name_addr = resolve_name_site(vtable.raw(), module_end);
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
        const std::size_t len = detail::read_name_seh(name_addr, out.data(), out.size(), module_end);
        if (len == 0)
            return std::nullopt;
        out.resize(len);
        return out;
    }

    std::size_t rtti::type_name_into(Address vtable, char *out, std::size_t out_len) noexcept
    {
        if (!out || out_len == 0)
            return 0;
        out[0] = '\0';
        std::uintptr_t module_end = 0;
        const std::uintptr_t name_addr = resolve_name_site(vtable.raw(), module_end);
        if (name_addr == 0)
            return 0;
        return detail::read_name_seh(name_addr, out, out_len, module_end);
    }

    rtti::NameRead rtti::type_name_checked(Address vtable, char *out, std::size_t out_len) noexcept
    {
        NameRead result;
        if (!out || out_len == 0)
            return result;
        out[0] = '\0';
        std::uintptr_t module_end = 0;
        const std::uintptr_t name_addr = resolve_name_site(vtable.raw(), module_end);
        if (name_addr == 0)
            return result;

        const std::size_t written = detail::read_name_seh(name_addr, out, out_len, module_end);
        if (written == 0)
        {
            // A one-byte destination has room only for the terminator. Distinguish that zero-length truncation from a
            // read failure; an empty RTTI name, while not emitted by MSVC, is still a complete read.
            if (out_len == 1)
            {
                char first = 1;
                if (DetourModKit::detail::guarded_read_bytes(name_addr, &first, 1))
                    result.status = (first == '\0') ? NameStatus::Ok : NameStatus::Truncated;
            }
            return result;
        }
        result.written = written;

        // read_name_seh stopped at the first NUL or at the length cap. The byte immediately after the copied prefix
        // decides which: the terminator (complete) or another name byte (truncated). A byte at or past the module
        // boundary, or one that faults, means the name has no in-module terminator within the cap -- not a trustworthy
        // whole name, so report Truncated so an identity comparison rejects it rather than matching a prefix.
        const std::uintptr_t next = name_addr + written;
        if (module_end != 0 && next >= module_end)
        {
            result.status = NameStatus::Truncated;
            return result;
        }
        char probe = 1;
        if (!DetourModKit::detail::guarded_read_bytes(next, &probe, 1))
        {
            result.status = NameStatus::Truncated;
            return result;
        }
        result.status = (probe == '\0') ? NameStatus::Ok : NameStatus::Truncated;
        return result;
    }

    bool rtti::vtable_is_type(Address vtable, std::string_view expected) noexcept
    {
        if (expected.empty() || expected.size() >= MAX_TYPE_NAME_LEN)
            return false;

        std::uintptr_t module_end = 0;
        const std::uintptr_t name_addr = resolve_name_site(vtable.raw(), module_end);
        if (name_addr == 0)
            return false;

        // Read expected.size() + 1 bytes to capture the terminating NUL. A name that lacks the NUL at expected.size()
        // is either longer (a superstring) or unreadable past that point; both are rejected.
        char buf[MAX_TYPE_NAME_LEN + 1];
        const std::size_t need = expected.size() + 1;
        // Fail closed if the compare would read to or past the owning module's end. A matching in-module name has its
        // NUL before module_end, so a name buffer within `need` bytes of the boundary cannot equal `expected`, and the
        // read must not spill into an adjacent mapped image. (module_end > name_addr is guaranteed by resolve_col_site;
        // the <= guard is defensive.)
        if (module_end <= name_addr || module_end - name_addr < need)
            return false;
        if (!DetourModKit::detail::guarded_read_bytes(name_addr, buf, need))
            return false;
        if (buf[expected.size()] != '\0')
            return false;
        return std::memcmp(buf, expected.data(), expected.size()) == 0;
    }

    void rtti::PointerTableCache::reset() noexcept
    {
        while (m_writer.test_and_set(std::memory_order_acquire))
            (void)::SwitchToThread();

        const std::uint32_t sequence = m_seq.load(std::memory_order_relaxed);
        m_seq.store(sequence + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        m_vtable.store(Address{}, std::memory_order_relaxed);
        m_image_base.store(Address{}, std::memory_order_relaxed);
        m_generation.store(0, std::memory_order_relaxed);
        m_epoch.fetch_add(1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        m_seq.store(sequence + 2, std::memory_order_relaxed);
        m_writer.clear(std::memory_order_release);
    }

    std::optional<Address> rtti::find_in_pointer_table(Address table, std::size_t slot_count, std::string_view expected,
                                                       std::atomic<Address> *vtable_cache, std::size_t stride) noexcept
    {
        if (table.raw() < detail::MIN_VALID_PTR || slot_count == 0 || expected.empty())
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
        const std::uintptr_t table_raw = table.raw();
        const std::uintptr_t span = static_cast<std::uintptr_t>(slot_count * stride);
        if (table_raw + span < table_raw)
            return std::nullopt;

        Address cached_vt{};
        if (vtable_cache)
            cached_vt = vtable_cache->load(std::memory_order_relaxed);

        const auto scan = [&](Address warm_vtable) noexcept -> std::optional<Address>
        {
            for (std::size_t i = 0; i < slot_count; ++i)
            {
                const std::uintptr_t slot_addr = table_raw + i * stride;
                const auto obj_opt = DetourModKit::detail::guarded_read<std::uintptr_t>(slot_addr);
                if (!obj_opt || *obj_opt < detail::MIN_VALID_PTR)
                    continue;
                const std::uintptr_t obj = *obj_opt;

                const auto vt_opt = DetourModKit::detail::guarded_read<std::uintptr_t>(obj);
                if (!vt_opt || *vt_opt < detail::MIN_VALID_PTR)
                    continue;
                const Address vt{*vt_opt};

                if (warm_vtable)
                {
                    if (vt == warm_vtable)
                        return Address{obj};
                    continue;
                }

                if (vtable_is_type(vt, expected))
                {
                    if (vtable_cache)
                        vtable_cache->store(vt, std::memory_order_relaxed);
                    return Address{obj};
                }
            }
            return std::nullopt;
        };

        if (cached_vt)
        {
            if (const auto warm = scan(cached_vt))
                return warm;

            // No slot carried the cached vtable. Clear only the value this call observed, then run one cold pass so a
            // remapped table refreshes immediately instead of remaining wedged on a stale address.
            if (vtable_cache)
            {
                Address expected_cache = cached_vt;
                (void)vtable_cache->compare_exchange_strong(expected_cache, Address{}, std::memory_order_relaxed);
            }
        }
        return scan(Address{});
    }

    std::optional<Address> rtti::find_in_pointer_table(Address table, std::size_t slot_count, std::string_view expected,
                                                       PointerTableCache &cache, std::size_t stride) noexcept
    {
        struct CacheSnapshot
        {
            Address vtable{};
            Address image_base{};
            std::uint64_t generation{0};
            std::uint64_t epoch{0};
        };

        const auto load_cache = [&cache]() noexcept -> CacheSnapshot
        {
            constexpr std::size_t MAX_ATTEMPTS = 16;
            for (std::size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt)
            {
                const std::uint32_t sequence = cache.m_seq.load(std::memory_order_acquire);
                if ((sequence & 1U) != 0U)
                    continue;
                const CacheSnapshot snapshot{
                    cache.m_vtable.load(std::memory_order_relaxed), cache.m_image_base.load(std::memory_order_relaxed),
                    cache.m_generation.load(std::memory_order_relaxed), cache.m_epoch.load(std::memory_order_relaxed)};
                std::atomic_thread_fence(std::memory_order_acquire);
                if (cache.m_seq.load(std::memory_order_relaxed) == sequence)
                    return snapshot;
            }
            return {};
        };

        const auto publish_cache = [&cache](CacheSnapshot desired, CacheSnapshot expected_snapshot) noexcept
        {
            if (cache.m_writer.test_and_set(std::memory_order_acquire))
                return;
            if (cache.m_vtable.load(std::memory_order_relaxed) != expected_snapshot.vtable ||
                cache.m_image_base.load(std::memory_order_relaxed) != expected_snapshot.image_base ||
                cache.m_generation.load(std::memory_order_relaxed) != expected_snapshot.generation ||
                cache.m_epoch.load(std::memory_order_relaxed) != expected_snapshot.epoch)
            {
                cache.m_writer.clear(std::memory_order_release);
                return;
            }
            const std::uint32_t sequence = cache.m_seq.load(std::memory_order_relaxed);
            cache.m_seq.store(sequence + 1, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            cache.m_vtable.store(desired.vtable, std::memory_order_relaxed);
            cache.m_image_base.store(desired.image_base, std::memory_order_relaxed);
            cache.m_generation.store(desired.generation, std::memory_order_relaxed);
            std::atomic_thread_fence(std::memory_order_release);
            cache.m_seq.store(sequence + 2, std::memory_order_relaxed);
            cache.m_writer.clear(std::memory_order_release);
        };

        for (std::size_t attempt = 0; attempt < 2; ++attempt)
        {
            const CacheSnapshot snapshot = load_cache();
            const bool warm = snapshot.vtable && snapshot.image_base && snapshot.generation != 0 &&
                              current_image_stamp(snapshot.image_base.raw()) == snapshot.generation;
            std::atomic<Address> candidate_cache{warm ? snapshot.vtable : Address{}};
            const auto hit = find_in_pointer_table(table, slot_count, expected, &candidate_cache, stride);
            if (!hit)
            {
                if (snapshot.vtable)
                    publish_cache({}, snapshot);
                return std::nullopt;
            }

            const Address candidate_vtable = candidate_cache.load(std::memory_order_relaxed);
            if (warm && candidate_vtable == snapshot.vtable)
            {
                if (current_image_stamp(snapshot.image_base.raw()) == snapshot.generation)
                    return hit;
                publish_cache({}, snapshot);
                continue;
            }

            const Region image_before = current_module_region(candidate_vtable);
            const std::uint64_t generation_before =
                image_before.base ? current_image_stamp(image_before.base.raw()) : 0;
            if (!image_before.base || generation_before == 0 || !vtable_is_type(candidate_vtable, expected))
            {
                publish_cache({}, snapshot);
                return std::nullopt;
            }

            const auto object_vtable = DetourModKit::detail::guarded_read<std::uintptr_t>(hit->raw());
            const Region image_after = current_module_region(candidate_vtable);
            const std::uint64_t generation_after = image_after.base ? current_image_stamp(image_after.base.raw()) : 0;
            if (!object_vtable || *object_vtable != candidate_vtable.raw() || image_after.base != image_before.base ||
                generation_after != generation_before)
            {
                publish_cache({}, snapshot);
                continue;
            }

            publish_cache({candidate_vtable, image_after.base, generation_after}, snapshot);
            return hit;
        }
        return std::nullopt;
    }

    namespace
    {
        // Upper bound on distinct sub-object vtables collected for one mangled name. Multiple/virtual inheritance
        // produces a handful at most; the cap keeps the reverse scan allocation-free (matches live in a stack array)
        // and bounds a pathological duplicate-type image.
        inline constexpr std::size_t MAX_REVERSE_MATCHES = 64;

        // Cap on the readable non-executable sections collected into the stack range buffer for one reverse sweep. A
        // normal PE keeps vtables and their RTTI meta-pointers in one or two sections (.rdata, .data), so this is
        // generous; a scope with more qualifying sections than fit reports Traversal::Saturated rather than silently
        // dropping the overflow.
        inline constexpr std::size_t MAX_RTTI_SCAN_RANGES = 32;

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

        [[nodiscard]] Region current_module_region(Address address) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *override_fn = DetourModKit::detail::g_rtti_module_region_override)
                return override_fn(address);
#endif
            return DetourModKit::detail::live_module_region(address);
        }

        /** @brief Reads the bounded PE identity fields at a known module base without consulting the loader. */
        [[nodiscard]] std::uint64_t read_image_stamp_from_base(std::uintptr_t module_base) noexcept
        {
            if (!DetourModKit::detail::is_plausible_ptr(module_base))
                return 0;

            const auto dos = DetourModKit::detail::guarded_read<IMAGE_DOS_HEADER>(module_base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
                static_cast<std::uint32_t>(dos->e_lfanew) > 0x100000U)
                return 0;
            const std::uintptr_t nt_addr = module_base + static_cast<std::uint32_t>(dos->e_lfanew);
            const auto nt = DetourModKit::detail::guarded_read<IMAGE_NT_HEADERS64>(nt_addr);
            if (!nt || nt->Signature != IMAGE_NT_SIGNATURE ||
                nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt->OptionalHeader.SizeOfImage == 0)
                return 0;

            const auto mix = [](std::uint64_t seed, std::uint64_t value) noexcept -> std::uint64_t
            {
                seed ^= value + 0x9E3779B97F4A7C15ULL + (seed << 6) + (seed >> 2);
                return seed;
            };
            std::uint64_t token = static_cast<std::uint64_t>(module_base);
            token = mix(token, static_cast<std::uint64_t>(nt->OptionalHeader.SizeOfImage));
            token = mix(token, static_cast<std::uint64_t>(nt->FileHeader.TimeDateStamp));
            return token == 0 ? 1 : token;
        }

        [[nodiscard]] std::uint64_t current_image_stamp(std::uintptr_t module_base) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (auto *override_fn = DetourModKit::detail::g_rtti_image_generation_override)
                return override_fn(module_base);
#endif
            return read_image_stamp_from_base(module_base);
        }

        /**
         * @brief Enumerates the module's readable, non-executable, non-discardable sections -- where MSVC keeps vtables
         *        and their
         *        RTTI meta-pointers (.rdata for a normal /GR image, .data for a packed or section-merged one).
         * @details .text is skipped on purpose: a vtable's [-1] COL meta-slot never lives in executable code, and
         *          sweeping code pages qword-by-qword would multiply the one-time cost for nothing. Every header field
         *          is bound- and signature-checked so a malformed or hostile image fails closed instead of being read
         *          through.
         * @return The number of ranges written into @p out; 0 means the PE headers could not be parsed and the caller
         *         falls back to the whole module image. @p completeness is set to @ref rtti::Traversal::Incomplete when
         *         a section header could not be read after a valid prefix, or @ref rtti::Traversal::Saturated when a
         *         qualifying section did not fit @p out; it is left @ref rtti::Traversal::Complete otherwise (including
         *         the 0-return, where the caller's whole-image fallback determines its own completeness).
         */
        std::size_t collect_rtti_scan_ranges(DetourModKit::detail::ModuleSpan mod, ScanRange *out, std::size_t cap,
                                             rtti::Traversal &completeness) noexcept
        {
            const auto dos = DetourModKit::detail::guarded_read<IMAGE_DOS_HEADER>(mod.base);
            if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return 0;

            const std::uintptr_t nt_offset = static_cast<std::uint32_t>(dos->e_lfanew);
            if (nt_offset >= mod.end - mod.base)
                return 0;
            const std::uintptr_t nt_addr = mod.base + nt_offset;
            // The NT headers must lie inside the image; a wild e_lfanew is the signature of a forged or truncated
            // header.
            if (!mod.contains(nt_addr) || mod.end - nt_addr < sizeof(IMAGE_NT_HEADERS64))
                return 0;

            const auto nt = DetourModKit::detail::guarded_read<IMAGE_NT_HEADERS64>(nt_addr);
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
            for (std::uint32_t i = 0; i < num_sections; ++i)
            {
                const std::uintptr_t hdr_addr =
                    sec_table + static_cast<std::uintptr_t>(i) * sizeof(IMAGE_SECTION_HEADER);
                // A section header that escapes the image, or one whose guarded read faults, truncates the enumeration
                // after a valid prefix: the sections past it are never examined, so a unique/absent verdict built on
                // this range set is not authoritative. Surface Incomplete rather than silently returning the prefix.
                if (!mod.contains(hdr_addr) || mod.end - hdr_addr < sizeof(IMAGE_SECTION_HEADER))
                {
                    completeness = rtti::Traversal::Incomplete;
                    break;
                }

                const auto sec = DetourModKit::detail::guarded_read<IMAGE_SECTION_HEADER>(hdr_addr);
                if (!sec)
                {
                    completeness = rtti::Traversal::Incomplete;
                    break;
                }

                const std::uint32_t ch = sec->Characteristics;
                const bool readable = (ch & IMAGE_SCN_MEM_READ) != 0;
                const bool executable = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
                const bool discardable = (ch & IMAGE_SCN_MEM_DISCARDABLE) != 0;
                if (!readable || executable || discardable)
                    continue;

                // Use the in-memory extent (VirtualAddress + VirtualSize), never the on-disk
                // PointerToRawData/SizeOfRawData: those are file offsets and do not survive section alignment once
                // mapped.
                if (sec->Misc.VirtualSize == 0)
                    continue;
                if (sec->VirtualAddress >= mod.end - mod.base)
                {
                    completeness = merge_traversal(completeness, rtti::Traversal::Incomplete);
                    continue;
                }
                const std::uintptr_t begin = mod.base + sec->VirtualAddress;
                if (sec->Misc.VirtualSize > mod.end - begin)
                {
                    completeness = merge_traversal(completeness, rtti::Traversal::Incomplete);
                    continue;
                }
                const std::uintptr_t end = begin + sec->Misc.VirtualSize;

                // A qualifying section that will not fit the caller's fixed range buffer means the sweep would omit a
                // region that could hold the type: report Saturated so the verdict is not treated as authoritative.
                if (count == cap)
                {
                    completeness = rtti::Traversal::Saturated;
                    break;
                }
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
         * @param module_end Exclusive end of the name's owning module; the compare fails closed rather than reading to
         *        or past it, so an edge-of-module name buffer cannot over-read into an adjacent mapped image.
         */
        [[nodiscard]] bool name_equals(std::uintptr_t name_addr, std::string_view mangled,
                                       std::uintptr_t module_end) noexcept
        {
            char buf[rtti::MAX_TYPE_NAME_LEN + 1];
            const std::size_t need = mangled.size() + 1;
            if (module_end <= name_addr || module_end - name_addr < need)
                return false;
            if (!DetourModKit::detail::guarded_read_bytes(name_addr, buf, need))
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
         *          points to an in-scope COL; the vtable that owns it is slot + 8, validated by the same COL prelude
         *          the forward walker uses, so the in-range pre-filter only spares a deeper read and never decides
         *          correctness.
         * @param mod The scan SCOPE, used for the meta-slot pre-filter (a candidate's COL pointer must land in it).
         * @param owning The vtables' OWNING-MODULE span, used to validate each candidate (see the resolve_col_site
         *        call below). May be an invalid span, in which case each candidate resolves its own module.
         */
        void sweep_range_for_name(DetourModKit::detail::ModuleSpan mod, DetourModKit::detail::ModuleSpan owning,
                                  std::uintptr_t begin, std::uintptr_t end, std::string_view mangled, VtMatch *out,
                                  std::size_t cap, std::size_t &count, bool &page_unreadable) noexcept
        {
            // Image-resident pointer storage is 8-byte aligned, so only qword-aligned slots can hold a vtable
            // meta-pointer.
            std::uintptr_t addr = (begin + 7) & ~static_cast<std::uintptr_t>(7);

            while (addr + sizeof(std::uintptr_t) <= end && count < cap)
            {
                // Never let one guarded read cross a page boundary: an unmapped page then fails only its own chunk, not
                // the whole window.
                const std::uintptr_t page_end = (addr | rtti::detail::PAGE_MASK) + 1;
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
                if (!DetourModKit::detail::guarded_read_bytes(addr, buf, want * sizeof(std::uintptr_t)))
                {
                    // A page inside a qualifying section could not be read, so a meta-slot on it (and the vtable it
                    // anchors) is invisible to this sweep. Record the gap: a unique/absent verdict built on a sweep
                    // that skipped a page is not authoritative. The page is skipped (advance past it) rather than
                    // aborting, so the readable remainder of the range is still scanned.
                    page_unreadable = true;
                }
                else
                {
                    for (std::size_t j = 0; j < want && count < cap; ++j)
                    {
                        // Pre-filter: a meta-slot holds a pointer to a COL inside
                        // this module. Most qwords fail here without a second read.
                        if (!mod.contains(buf[j]))
                            continue;

                        const std::uintptr_t slot_addr = addr + j * sizeof(std::uintptr_t);
                        const std::uintptr_t candidate_vtable = slot_addr + sizeof(std::uintptr_t);

                        // Validate against the owning-module span the caller resolved once, not the scan scope `mod`:
                        // resolve_col_site cross-checks the recovered image base (col_addr - pSelf) against the module
                        // base and computes the TypeDescriptor / name addresses from module-base + RVA, so it needs the
                        // true module extent -- which a sub-range scope (a tight fixture window whose base is not the
                        // image base) is not. Passing the pre-resolved owning span hoists the per-candidate
                        // memory::module_of loader lookup out of the hot sweep; if that one-time resolve failed (owning
                        // invalid), fall back to the self-resolving overload so behaviour is unchanged.
                        rtti::detail::ColSite site;
                        const bool resolved_ok = owning.valid()
                                                     ? rtti::detail::resolve_col_site(candidate_vtable, owning, site)
                                                     : rtti::detail::resolve_col_site(candidate_vtable, site);
                        if (!resolved_ok)
                            continue;
                        if (!name_equals(site.name_addr, mangled, site.module_end))
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
        std::size_t scan_vtables_for_name(DetourModKit::detail::ModuleSpan mod, std::string_view mangled, VtMatch *out,
                                          std::size_t cap, rtti::Traversal &completeness) noexcept
        {
            if (!mod.valid() || mangled.empty() || mangled.size() >= rtti::MAX_TYPE_NAME_LEN)
            {
                completeness = merge_traversal(completeness, rtti::Traversal::Incomplete);
                return 0;
            }

            // Resolve the vtables' owning module once for the whole sweep. resolve_col_site needs the true module base
            // and extent (for the pSelf/base cross-check and RVA->VA), which is not the scan scope `mod`: a caller may
            // scope the sweep to a sub-range of the module (a tight fixture window), whose base is not the image base.
            // module_of at the scope base recovers the real owning module, shared by every candidate in the scope, so
            // the per-candidate loader lookup is hoisted here. An invalid result (the scope base is not in a loaded
            // module) leaves each candidate to resolve its own module in sweep_range_for_name, preserving behaviour.
            const DetourModKit::detail::ModuleSpan owning =
                DetourModKit::detail::module_span(DetourModKit::detail::live_module_region(Address{mod.base}));

            ScanRange ranges[MAX_RTTI_SCAN_RANGES];
            const std::size_t range_count = collect_rtti_scan_ranges(mod, ranges, MAX_RTTI_SCAN_RANGES, completeness);

            std::size_t count = 0;
            bool page_unreadable = false;
            if (range_count == 0)
            {
                // No usable scan window (the PE headers could not be parsed, or no readable non-executable section
                // qualified): sweep the whole image rather than report a confident-but-wrong "not found" for a packed
                // or section-merged binary. The whole-image sweep is a strict superset, and resolve_col_site still
                // validates every candidate.
                sweep_range_for_name(mod, owning, mod.base, mod.end, mangled, out, cap, count, page_unreadable);
            }
            else
            {
                for (std::size_t i = 0; i < range_count && count < cap; ++i)
                {
                    sweep_range_for_name(mod, owning, ranges[i].begin, ranges[i].end, mangled, out, cap, count,
                                         page_unreadable);
                }
            }

            // An unreadable page anywhere in the sweep means a match could have hidden on it; a match buffer that
            // filled to capacity means the same for the matches past the cap. Either makes a uniqueness or absence
            // verdict unsafe, so fold both into the completeness the caller gates on.
            if (page_unreadable)
                completeness = merge_traversal(completeness, rtti::Traversal::Incomplete);
            if (count == cap)
                completeness = merge_traversal(completeness, rtti::Traversal::Saturated);
            return count;
        }

        /**
         * @brief Sweeps one [begin,end) window and returns true when it finds any validated COL.
         * @details Mirrors the name sweep's page-bounded read, meta-slot pre-filter, and resolve_col_site validation,
         *          but returns on the first hit instead of collecting and deduping matches. The page-walk is duplicated
         *          from @ref sweep_range_for_name rather than factored into a shared callback-driven core: sharing one
         *          would complicate the security-critical name-resolve sweep purely to
         *          save the mechanical loop, and the two sweeps terminate differently (collect-to-cap versus first-hit
         *          exit). The validation authority, @ref resolve_col_site, IS shared, so the two paths cannot diverge
         *          on what counts as a resolvable COL; only the copied loop could drift, and a drift there is
         *          fail-safe (a missed COL yields a false negative that routes the caller to the raw-byte fallback).
         * @param mod The scan SCOPE, used for the in-scope meta-slot pre-filter.
         * @param owning The vtables' OWNING-MODULE span used for validation; may be invalid, in which case each
         *        candidate resolves its own module (mirrors @ref sweep_range_for_name).
         */
        bool sweep_range_for_first_col(DetourModKit::detail::ModuleSpan mod, DetourModKit::detail::ModuleSpan owning,
                                       std::uintptr_t begin, std::uintptr_t end, bool &page_unreadable) noexcept
        {
            std::uintptr_t addr = (begin + 7) & ~static_cast<std::uintptr_t>(7);

            while (addr + sizeof(std::uintptr_t) <= end)
            {
                // One guarded read per page: an unmapped page then fails only its own chunk, not the whole window.
                const std::uintptr_t page_end = (addr | rtti::detail::PAGE_MASK) + 1;
                const std::uintptr_t chunk_end = (page_end < end) ? page_end : end;
                const std::size_t qwords = static_cast<std::size_t>(chunk_end - addr) / sizeof(std::uintptr_t);
                if (qwords == 0)
                {
                    addr = chunk_end;
                    continue;
                }

                // A 4 KiB page holds at most 512 qwords.
                std::uintptr_t buf[512];
                const std::size_t want = (qwords < 512) ? qwords : 512;
                if (!DetourModKit::detail::guarded_read_bytes(addr, buf, want * sizeof(std::uintptr_t)))
                {
                    // An unreadable page hides any COL on it; record the gap so a "no records" answer built on this
                    // sweep is reported as Incomplete rather than an authoritative absence.
                    page_unreadable = true;
                }
                else
                {
                    for (std::size_t j = 0; j < want; ++j)
                    {
                        // A meta-slot holds a pointer to a COL inside this module; most qwords fail this cheap
                        // in-scope pre-filter without a second read.
                        if (!mod.contains(buf[j]))
                            continue;

                        const std::uintptr_t slot_addr = addr + j * sizeof(std::uintptr_t);
                        const std::uintptr_t candidate_vtable = slot_addr + sizeof(std::uintptr_t);

                        // resolve_col_site is the shared definition of "resolvable", so this predicate and the name
                        // resolver accept the same COL shapes.
                        rtti::detail::ColSite site;
                        const bool resolved_ok = owning.valid()
                                                     ? rtti::detail::resolve_col_site(candidate_vtable, owning, site)
                                                     : rtti::detail::resolve_col_site(candidate_vtable, site);
                        if (resolved_ok)
                            return true;
                    }
                }

                addr += want * sizeof(std::uintptr_t);
            }
            return false;
        }

        /**
         * @brief Reports whether @p mod holds any resolvable RTTI record, mirroring @ref scan_vtables_for_name's range
         *        selection but short-circuiting on the first validated COL.
         * @details Resolves the vtables' owning-module span once (exactly as @ref scan_vtables_for_name does at its
         *          scope base) so every candidate is validated against the true image base, then sweeps the same
         *          readable non-executable sections, with the identical whole-image fallback when the PE headers do not
         *          parse -- a packed or section-merged image, or a tight non-PE scope window. The caller
         *          (@ref rtti::region_has_rtti) has already proven @p mod valid.
         */
        rtti::RttiPresence scope_has_rtti(DetourModKit::detail::ModuleSpan mod) noexcept
        {
            const DetourModKit::detail::ModuleSpan owning =
                DetourModKit::detail::module_span(DetourModKit::detail::live_module_region(Address{mod.base}));

            rtti::Traversal completeness = rtti::Traversal::Complete;
            ScanRange ranges[MAX_RTTI_SCAN_RANGES];
            const std::size_t range_count = collect_rtti_scan_ranges(mod, ranges, MAX_RTTI_SCAN_RANGES, completeness);

            bool page_unreadable = false;
            if (range_count == 0)
            {
                // No parseable section table (packed / section-merged / a non-PE scope window): sweep the whole image
                // as a strict superset, exactly as scan_vtables_for_name does on the same condition.
                if (sweep_range_for_first_col(mod, owning, mod.base, mod.end, page_unreadable))
                    return rtti::RttiPresence::Present;
            }
            else
            {
                for (std::size_t i = 0; i < range_count; ++i)
                {
                    if (sweep_range_for_first_col(mod, owning, ranges[i].begin, ranges[i].end, page_unreadable))
                        return rtti::RttiPresence::Present;
                }
            }

            // No record was found. Only call that an authoritative absence when the sweep was complete: a faulted
            // section header (in `completeness`) or an unreadable page (`page_unreadable`) could have hidden the only
            // record, so report Incomplete instead of a false Absent.
            if (page_unreadable)
                completeness = merge_traversal(completeness, rtti::Traversal::Incomplete);
            return (completeness == rtti::Traversal::Complete) ? rtti::RttiPresence::Absent
                                                               : rtti::RttiPresence::Incomplete;
        }
    } // anonymous namespace

    std::optional<Address> rtti::vtable_for_type(std::string_view mangled, Region range) noexcept
    {
        VtMatch matches[MAX_REVERSE_MATCHES];
        rtti::Traversal completeness = rtti::Traversal::Complete;
        const std::size_t match_count = scan_vtables_for_name(DetourModKit::detail::module_span(range), mangled,
                                                              matches, MAX_REVERSE_MATCHES, completeness);

        // A unique or absent verdict is the inverse of vtable_is_type and is trustworthy only across a COMPLETE sweep.
        // An Incomplete sweep (a faulted section header or an unreadable page) or a Saturated one (the section-range or
        // match buffer filled) could hide a second distinct primary -- making a "unique" answer wrong -- or the only
        // primary -- making an "absent" answer wrong. Fail closed rather than authorize a verdict from a partial sweep;
        // match-buffer exhaustion is reported as Traversal::Saturated by the same completeness gate.
        if (completeness != rtti::Traversal::Complete)
            return std::nullopt;

        // The primary vtable is the COL.offset == 0 sub-object: the value an object pointer's first qword holds for a
        // most-derived instance. More than one distinct primary for the same name (a type linked into the image twice)
        // is ambiguous; fail closed rather than return an arbitrary one.
        std::optional<std::uintptr_t> primary;
        for (std::size_t i = 0; i < match_count; ++i)
        {
            if (matches[i].col_offset != 0)
                continue;
            if (primary && *primary != matches[i].vtable)
                return std::nullopt;
            primary = matches[i].vtable;
        }

        if (!primary)
            return std::nullopt;
        return Address{*primary};
    }

    rtti::VtablesResult rtti::vtables_for_type_checked(std::string_view mangled, Address *out, std::size_t out_cap,
                                                       Region range) noexcept
    {
        if (!out)
            out_cap = 0;

        VtMatch matches[MAX_REVERSE_MATCHES];
        rtti::Traversal completeness = rtti::Traversal::Complete;
        const std::size_t match_count = scan_vtables_for_name(DetourModKit::detail::module_span(range), mangled,
                                                              matches, MAX_REVERSE_MATCHES, completeness);

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
            out[i] = Address{matches[i].vtable};
        return VtablesResult{match_count, completeness};
    }

    std::size_t rtti::vtables_for_type(std::string_view mangled, Address *out, std::size_t out_cap,
                                       Region range) noexcept
    {
        // Best-effort count-only face over the checked form: it discards the completeness, so a caller that must
        // distinguish an authoritative absence from a truncated sweep uses vtables_for_type_checked instead.
        return vtables_for_type_checked(mangled, out, out_cap, range).count;
    }

    bool rtti::region_has_rtti(Region range) noexcept
    {
        // true only on a found record (sound regardless of completeness); Absent and Incomplete both collapse to the
        // fail-closed "no record found, use the raw-byte fallback" answer, the same one an invalid range receives.
        return region_rtti_presence(range) == RttiPresence::Present;
    }

    rtti::RttiPresence rtti::region_rtti_presence(Region range) noexcept
    {
        const auto mod = DetourModKit::detail::module_span(range);
        // No sweep can establish absence from an invalid range.
        if (!mod.valid())
            return RttiPresence::Incomplete;
        return scope_has_rtti(mod);
    }

    std::uint64_t rtti::image_generation(Address addr) noexcept
    {
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (auto *override_fn = DetourModKit::detail::g_rtti_image_generation_override)
            return override_fn(addr.raw());
#endif
        const Region module = current_module_region(addr);
        return module.base ? read_image_stamp_from_base(module.base.raw()) : 0;
    }

    rtti::TypeIdentity::TypeIdentity(std::string_view mangled, Region range) : m_mangled(mangled), m_range(range)
    {
        const Region module = current_module_region(range.base);
        m_tracks_module_range = module.base == range.base && module.size == range.size;
    }

    void rtti::TypeIdentity::invalidate() noexcept
    {
        while (m_cache_writer.test_and_set(std::memory_order_acquire))
            (void)::SwitchToThread();
        m_cache_epoch.fetch_add(1, std::memory_order_acq_rel);
        m_resolved.store(false, std::memory_order_release);
        m_cached.store(Address{}, std::memory_order_relaxed);
        m_image_stamp.store(0, std::memory_order_relaxed);
        m_image_base.store(Address{}, std::memory_order_relaxed);
        m_last_attempt_ms.store(0, std::memory_order_relaxed);
        m_cache_writer.clear(std::memory_order_release);
    }

    std::optional<Address> rtti::TypeIdentity::vtable() const noexcept
    {
        const std::uint64_t cache_epoch = m_cache_epoch.load(std::memory_order_acquire);
        const auto resolve_and_cache = [this](std::uint64_t expected_epoch) -> std::optional<Address>
        {
            Region resolve_range = m_range;
            if (m_tracks_module_range)
            {
                resolve_range = current_module_region(m_range.base);
                if (!resolve_range.base || resolve_range.size == 0)
                    return std::nullopt;
            }

            const Region image_before = current_module_region(resolve_range.base);
            const std::uint64_t stamp_before = image_before.base ? current_image_stamp(image_before.base.raw()) : 0;
            const auto resolved = vtable_for_type(m_mangled, resolve_range);
            if (!resolved)
                return std::nullopt;

            const Region image_after = current_module_region(*resolved);
            const std::uint64_t stamp_after = image_after.base ? current_image_stamp(image_after.base.raw()) : 0;
            const bool module_backed_before = image_before.base && image_before.size != 0;
            const bool module_backed_after = image_after.base && image_after.size != 0;
            if (module_backed_before != module_backed_after || image_before.base != image_after.base ||
                stamp_before != stamp_after || (module_backed_after && stamp_after == 0))
                return std::nullopt;

            if (m_cache_writer.test_and_set(std::memory_order_acquire))
                return std::nullopt;
            if (m_cache_epoch.load(std::memory_order_acquire) != expected_epoch)
            {
                m_cache_writer.clear(std::memory_order_release);
                return std::nullopt;
            }
            m_image_base.store(image_after.base, std::memory_order_relaxed);
            m_image_stamp.store(stamp_after, std::memory_order_relaxed);
            m_cached.store(*resolved, std::memory_order_relaxed);
            m_resolved.store(true, std::memory_order_release);
            m_cache_writer.clear(std::memory_order_release);
            return resolved;
        };

        if (m_resolved.load(std::memory_order_acquire))
        {
            const Address image_base = m_image_base.load(std::memory_order_relaxed);
            const std::uint64_t image_stamp = m_image_stamp.load(std::memory_order_relaxed);
            if (image_stamp != 0 && current_image_stamp(image_base.raw()) != image_stamp)
            {
                if (m_cache_writer.test_and_set(std::memory_order_acquire))
                    return std::nullopt;
                if (m_cache_epoch.load(std::memory_order_acquire) != cache_epoch)
                {
                    m_cache_writer.clear(std::memory_order_release);
                    return std::nullopt;
                }
                const std::uint64_t next_epoch = m_cache_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
                m_resolved.store(false, std::memory_order_release);
                m_cached.store(Address{}, std::memory_order_relaxed);
                m_image_stamp.store(0, std::memory_order_relaxed);
                m_image_base.store(Address{}, std::memory_order_relaxed);
                m_cache_writer.clear(std::memory_order_release);
                return resolve_and_cache(next_epoch);
            }
            const Address cached = m_cached.load(std::memory_order_relaxed);
            if (m_cache_epoch.load(std::memory_order_acquire) != cache_epoch ||
                !m_resolved.load(std::memory_order_acquire))
                return std::nullopt;
            return cached ? std::optional<Address>(cached) : std::nullopt;
        }

        // Miss path. vtable_for_type sweeps every RTTI-bearing section -- a heavy walk -- so throttle the re-sweep:
        // after a miss, skip until RESOLVE_RETRY_COOLDOWN_MS has elapsed, turning a per-frame full-module scan for an
        // absent type into at most one scan per cooldown while still eventually retrying. last == 0 is the
        // never-attempted sentinel; the now >= last guard keeps a non-monotonic clock from underflowing into a skip.
        const std::uint64_t now = rtti_now_ms();
        if (m_cache_writer.test_and_set(std::memory_order_acquire))
            return std::nullopt;
        if (m_cache_epoch.load(std::memory_order_acquire) != cache_epoch)
        {
            m_cache_writer.clear(std::memory_order_release);
            return std::nullopt;
        }
        const std::uint64_t last = m_last_attempt_ms.load(std::memory_order_acquire);
        if (last != 0 && now >= last && (now - last) < RESOLVE_RETRY_COOLDOWN_MS)
        {
            m_cache_writer.clear(std::memory_order_release);
            return std::nullopt;
        }
        m_last_attempt_ms.store(now == 0 ? 1 : now, std::memory_order_release);
        m_cache_writer.clear(std::memory_order_release);
        return resolve_and_cache(cache_epoch);
    }

    bool rtti::TypeIdentity::matches(Address vtable) const noexcept
    {
        const auto resolved = TypeIdentity::vtable();
        return resolved.has_value() && *resolved == vtable;
    }
} // namespace DetourModKit
