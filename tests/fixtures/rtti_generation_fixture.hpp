#ifndef DETOURMODKIT_TESTS_FIXTURES_RTTI_GENERATION_FIXTURE_HPP
#define DETOURMODKIT_TESTS_FIXTURES_RTTI_GENERATION_FIXTURE_HPP

/**
 * @file rtti_generation_fixture.hpp
 * @brief Shared contract between the fixed-base RTTI fixture DLL and the tests that map it.
 * @details Two variants of one DLL are produced from a single link. They carry the same image base, SizeOfImage, and PE
 *          TimeDateStamp, and differ only in a section header and in the mangled type name their RTTI graph publishes.
 *          That is precisely the section-layout replacement an identity built from base, size, and timestamp alone
 *          cannot see, and it is what the public @ref DetourModKit::rtti::image_generation contract promises to catch.
 *
 *          The RTTI graph is written at runtime rather than compiled in, because the MSVC COL/TypeDescriptor layout
 *          the DMK walker reads is not what the GNU toolchain emits. Building it by hand keeps one fixture valid on
 *          both toolchains.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>

namespace dmk_test
{
    /**
     * @brief Mangled type name in variant A.
     * @details The variants differ in exactly one character, so their lengths match and the post-link rewrite is a
     *          single in-place byte patch.
     */
    inline constexpr const char *RTTI_FIXTURE_TYPE_A = ".?AVDmkRttiGenerationFixtureA@@";
    inline constexpr const char *RTTI_FIXTURE_TYPE_B = ".?AVDmkRttiGenerationFixtureB@@";

    /**
     * @brief Slot in the fixture's pointer table that holds the object pointer; the others are null decoys.
     * @details The object's first qword is the vtable, which is the indirection a real pointer table has.
     */
    inline constexpr std::size_t RTTI_FIXTURE_TABLE_SLOTS = 4;
    inline constexpr std::size_t RTTI_FIXTURE_VTABLE_SLOT = 2;

    inline constexpr const char *RTTI_FIXTURE_VARIANT_A = "dmk_rtti_gen_a.dll";
    inline constexpr const char *RTTI_FIXTURE_VARIANT_B = "dmk_rtti_gen_b.dll";

    /**
     * @class GenerationFixtureModule
     * @brief Loads one fixture variant and exposes the RTTI graph it lays down inside its own image.
     * @details Deliberately not copyable or movable: the whole point of the fixture is that only one variant is mapped
     *          at the shared base at a time, so an accidental second live handle would defeat the test it serves.
     */
    class GenerationFixtureModule
    {
    public:
        explicit GenerationFixtureModule(const char *file_name) : m_handle(::LoadLibraryA(file_name))
        {
            if (m_handle == nullptr)
            {
                return;
            }
            m_prepare = reinterpret_cast<UintFn>(
                reinterpret_cast<void *>(::GetProcAddress(m_handle, "dmk_rtti_fixture_prepare")));
            m_vtable = reinterpret_cast<UintFn>(
                reinterpret_cast<void *>(::GetProcAddress(m_handle, "dmk_rtti_fixture_vtable")));
            m_table = reinterpret_cast<UintFn>(
                reinterpret_cast<void *>(::GetProcAddress(m_handle, "dmk_rtti_fixture_table")));
            m_type_name = reinterpret_cast<NameFn>(
                reinterpret_cast<void *>(::GetProcAddress(m_handle, "dmk_rtti_fixture_type_name")));
        }

        ~GenerationFixtureModule() { release(); }

        GenerationFixtureModule(const GenerationFixtureModule &) = delete;
        GenerationFixtureModule &operator=(const GenerationFixtureModule &) = delete;
        GenerationFixtureModule(GenerationFixtureModule &&) = delete;
        GenerationFixtureModule &operator=(GenerationFixtureModule &&) = delete;

        [[nodiscard]] bool ok() const noexcept
        {
            return m_handle != nullptr && m_prepare != nullptr && m_vtable != nullptr && m_table != nullptr &&
                   m_type_name != nullptr;
        }

        /// Lays out the RTTI graph and returns the vtable address, or 0 when the module could not resolve its base.
        std::uintptr_t prepare() const { return m_prepare(); }

        [[nodiscard]] std::uintptr_t vtable() const { return m_vtable(); }
        [[nodiscard]] std::uintptr_t table() const { return m_table(); }
        [[nodiscard]] const char *type_name() const { return m_type_name(); }
        [[nodiscard]] std::uintptr_t base() const noexcept { return reinterpret_cast<std::uintptr_t>(m_handle); }

        /// Unmaps the variant so the next one can claim the shared base. Idempotent.
        void release()
        {
            if (m_handle != nullptr)
            {
                ::FreeLibrary(m_handle);
                m_handle = nullptr;
            }
            m_prepare = nullptr;
            m_vtable = nullptr;
            m_table = nullptr;
            m_type_name = nullptr;
        }

    private:
        using UintFn = std::uintptr_t (*)();
        using NameFn = const char *(*)();

        HMODULE m_handle{nullptr};
        UintFn m_prepare{nullptr};
        UintFn m_vtable{nullptr};
        UintFn m_table{nullptr};
        NameFn m_type_name{nullptr};
    };

    /**
     * @class SameBaseSwap
     * @brief Maps variant A, then replaces it with variant B at the same base.
     * @details Both steps report failure rather than throwing, because a loader that relocated the second variant
     *          leaves an ordinary base change, which a base-only identity already catches. A case built on this must
     *          assert the swap succeeded, or it would pass without reproducing the replacement it exists to measure.
     */
    class SameBaseSwap
    {
    public:
        [[nodiscard]] bool load_a()
        {
            m_module = std::make_unique<GenerationFixtureModule>(RTTI_FIXTURE_VARIANT_A);
            if (!m_module->ok() || m_module->prepare() == 0)
            {
                return false;
            }
            m_base = m_module->base();
            return true;
        }

        [[nodiscard]] bool swap_to_b()
        {
            m_module.reset();
            m_module = std::make_unique<GenerationFixtureModule>(RTTI_FIXTURE_VARIANT_B);
            if (!m_module->ok() || m_module->prepare() == 0)
            {
                return false;
            }
            return m_module->base() == m_base;
        }

        [[nodiscard]] GenerationFixtureModule &module() const noexcept { return *m_module; }
        [[nodiscard]] std::uintptr_t base() const noexcept { return m_base; }

    private:
        std::unique_ptr<GenerationFixtureModule> m_module;
        std::uintptr_t m_base{0};
    };
} // namespace dmk_test

#endif // DETOURMODKIT_TESTS_FIXTURES_RTTI_GENERATION_FIXTURE_HPP
