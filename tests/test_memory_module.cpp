#include "DetourModKit/address.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/region.hpp"

// White-box engine seams for the lifecycle-generation and module-name conversion tests.
#include "internal/lifecycle_context.hpp"
#include "internal/module_name.hpp"

// Deterministic thread-local out-of-memory injection and allocation count for the is_module_loaded allocation-failure
// test and the loader-boundary proof.
#include "test_alloc_probe.hpp"

// Shared [B-100] loader-probe scope.
#include "fixtures/loader_lock_scope.hpp"

// Completed same-base module replacement: two variants of one link that claim the same reserved base in turn.
#include "fixtures/rtti_generation_fixture.hpp"
#include "fixtures/scratch_page.hpp"

#include <gtest/gtest.h>
#include <windows.h>
#include <process.h>

#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "fixtures/memory_fixture.hpp"
using namespace dmk_test::memory_fixture;

using namespace DetourModKit;

namespace
{
    class ImageSizeOverride
    {
    public:
        explicit ImageSizeOverride(HMODULE module) noexcept
        {
            auto *const base = reinterpret_cast<std::byte *>(module);
            auto *const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return;
            }
            m_size = &nt->OptionalHeader.SizeOfImage;
            m_original_size = *m_size;
            if (VirtualProtect(m_size, sizeof(*m_size), PAGE_READWRITE, &m_original_protection) == FALSE)
            {
                m_size = nullptr;
            }
        }

        ~ImageSizeOverride() noexcept
        {
            if (m_size != nullptr)
            {
                *m_size = m_original_size;
                DWORD ignored = 0;
                (void)VirtualProtect(m_size, sizeof(*m_size), m_original_protection, &ignored);
            }
        }

        ImageSizeOverride(const ImageSizeOverride &) = delete;
        ImageSizeOverride &operator=(const ImageSizeOverride &) = delete;
        ImageSizeOverride(ImageSizeOverride &&) = delete;
        ImageSizeOverride &operator=(ImageSizeOverride &&) = delete;

        [[nodiscard]] bool valid() const noexcept { return m_size != nullptr; }
        [[nodiscard]] DWORD original_size() const noexcept { return m_original_size; }
        void set(DWORD size) noexcept { *m_size = size; }

    private:
        DWORD *m_size{nullptr};
        DWORD m_original_size{0};
        DWORD m_original_protection{0};
    };
} // namespace

// Region / module_of / Region::own / Region::host

TEST_F(MemoryTest, ModuleRange_DefaultIsInvalid)
{
    Region range;
    EXPECT_EQ(range.size, 0u);
    EXPECT_FALSE(static_cast<bool>(range.base));
    EXPECT_EQ(range.base.raw(), 0u);
    EXPECT_EQ(range.end().raw(), 0u);
}

TEST_F(MemoryTest, ModuleRange_ContainsRejectsInvalid)
{
    Region range;
    EXPECT_FALSE(range.contains(Address{static_cast<std::uintptr_t>(0x1000)}));
}

TEST_F(MemoryTest, ModuleRange_ContainsBoundary)
{
    constexpr Region range{Address{static_cast<std::uintptr_t>(0x10000)}, 0x10000};
    EXPECT_TRUE(range.contains(Address{static_cast<std::uintptr_t>(0x10000)}));
    EXPECT_TRUE(range.contains(Address{static_cast<std::uintptr_t>(0x1FFFF)}));
    EXPECT_FALSE(range.contains(Address{static_cast<std::uintptr_t>(0x20000)}));
    EXPECT_FALSE(range.contains(Address{static_cast<std::uintptr_t>(0xFFFF)}));
}

TEST_F(MemoryTest, ModuleRange_ConstexprValid)
{
    static_assert(Region{Address{static_cast<std::uintptr_t>(0x10000)}, 0x10000}.size != 0);
    static_assert(Region{Address{static_cast<std::uintptr_t>(0x1000)}, 0x1000}.contains(
        Address{static_cast<std::uintptr_t>(0x1500)}
    ));
}

TEST_F(MemoryTest, ModuleRangeFor_NullReturnsNullopt)
{
    const Region range = memory::module_of(Address{nullptr});
    EXPECT_EQ(range.size, 0u);
    EXPECT_FALSE(static_cast<bool>(range.base));
}

TEST_F(MemoryTest, ModuleRangeFor_OwnFunctionResolves)
{
    // The test executable is a loaded module. Its module range must contain the queried address.
    const Address probe{reinterpret_cast<const void *>(&memory::module_of)};
    const Region range = memory::module_of(probe);
    ASSERT_NE(range.size, 0u);
    EXPECT_TRUE(range.contains(probe));
}

TEST_F(MemoryTest, ModuleRangeFor_HeapAddressReturnsNullopt)
{
    // The heap address belongs to no loaded image. Its module query must produce an empty Region.
    auto buffer = std::make_unique<int>(42);
    const Region range = memory::module_of(Address{buffer.get()});
    EXPECT_EQ(range.size, 0u);
    EXPECT_FALSE(static_cast<bool>(range.base));
}

TEST_F(MemoryTest, ModuleRangeFor_RepeatedLookupIsConsistent)
{
    const Address probe{reinterpret_cast<const void *>(&Region::own)};
    const Region first = memory::module_of(probe);
    ASSERT_NE(first.size, 0u);

    const Region second = memory::module_of(probe);
    ASSERT_NE(second.size, 0u);

    EXPECT_EQ(first.base.raw(), second.base.raw());
    EXPECT_EQ(first.end().raw(), second.end().raw());
}

// The module handle is an image base that can be reused within one generation. The cases pin that generation while the
// live extent changes.
TEST_F(MemoryTest, ModuleRangeFor_SameGenerationExtentChangeIsVisibleImmediately)
{
    const HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    ImageSizeOverride image_size{host};
    ASSERT_TRUE(image_size.valid());
    ASSERT_GT(image_size.original_size(), 0x2000u);
    ASSERT_LE(image_size.original_size(), std::numeric_limits<DWORD>::max() - 0x1000u);

    auto &lifecycle = DetourModKit::detail::lifecycle();
    const std::uint64_t generation = lifecycle.generation();

    const Address probe{reinterpret_cast<const void *>(&memory::module_of)};
    ASSERT_EQ(memory::module_of(probe).size, image_size.original_size());

    const DWORD larger_size = image_size.original_size() + 0x1000u;
    image_size.set(larger_size);
    EXPECT_EQ(memory::module_of(probe).size, larger_size);

    const DWORD smaller_size = image_size.original_size() - 0x1000u;
    image_size.set(smaller_size);
    EXPECT_EQ(memory::module_of(probe).size, smaller_size);

    image_size.set(image_size.original_size());
    EXPECT_EQ(memory::module_of(probe).size, image_size.original_size());
    EXPECT_EQ(lifecycle.generation(), generation)
        << "the case proves same-generation freshness, so a generation advance would void it";
}

// The Region factories share the resolver with module_of, so the named-region consumers must observe the same
// extent change without a generation advance.
TEST_F(MemoryTest, NamedRegionConsumers_SeeTheSameGenerationExtentChange)
{
    const HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    ImageSizeOverride image_size{host};
    ASSERT_TRUE(image_size.valid());
    ASSERT_LE(image_size.original_size(), std::numeric_limits<DWORD>::max() - 0x1000u);

    wchar_t host_path[MAX_PATH];
    const DWORD length = GetModuleFileNameW(host, host_path, MAX_PATH);
    ASSERT_NE(length, 0u);
    ASSERT_LT(length, static_cast<DWORD>(MAX_PATH));
    const std::wstring_view path_view{host_path, length};
    const std::size_t separator = path_view.find_last_of(L"\\/");
    const std::wstring host_name(separator == std::wstring_view::npos ? path_view : path_view.substr(separator + 1));
    std::string host_name_narrow;
    host_name_narrow.reserve(host_name.size());
    for (const wchar_t wide : host_name)
    {
        ASSERT_LT(static_cast<unsigned>(wide), 0x80u) << "the test binary name must be ASCII for this lookup";
        host_name_narrow.push_back(static_cast<char>(wide));
    }

    auto &lifecycle = DetourModKit::detail::lifecycle();
    const std::uint64_t generation = lifecycle.generation();

    ASSERT_EQ(Region::host().size, image_size.original_size());
    ASSERT_EQ(Region::module_named(host_name_narrow).size, image_size.original_size());
    ASSERT_EQ(Region::own().size, image_size.original_size());

    const DWORD larger_size = image_size.original_size() + 0x1000u;
    image_size.set(larger_size);
    EXPECT_EQ(Region::host().size, larger_size);
    EXPECT_EQ(Region::module_named(host_name_narrow).size, larger_size);
    EXPECT_EQ(Region::own().size, larger_size);

    image_size.set(image_size.original_size());
    EXPECT_EQ(Region::host().size, image_size.original_size());
    EXPECT_EQ(lifecycle.generation(), generation);
}

// Variant B replaces A at the identical base. Both linked images share SizeOfImage, so the fixture edits B's
// OptionalHeader.SizeOfImage to expose stale extents.
TEST_F(MemoryTest, ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent)
{
    dmk_test::SameBaseSwap swap;
    if (!swap.load_a())
    {
        GTEST_SKIP() << "the fixed-base fixture did not map variant A at its reserved base";
    }

    const std::uintptr_t base = swap.base();
    const std::size_t size_a = memory::module_of(Address{base}).size;
    ASSERT_NE(size_a, 0u);
    ASSERT_EQ(Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A).size, size_a);
    ASSERT_LE(size_a, static_cast<std::size_t>(std::numeric_limits<DWORD>::max()) - 0x1000u);

    auto &lifecycle = DetourModKit::detail::lifecycle();
    const std::uint64_t generation = lifecycle.generation();

    if (!swap.swap_to_b())
    {
        GTEST_SKIP() << "variant B did not claim variant A's base";
    }
    ASSERT_EQ(swap.base(), base);

    // Declared after the swap so it is destroyed before the module it patches is unmapped.
    ImageSizeOverride replacement_size{reinterpret_cast<HMODULE>(base)};
    ASSERT_TRUE(replacement_size.valid());
    ASSERT_EQ(static_cast<std::size_t>(replacement_size.original_size()), size_a);
    const DWORD size_b = static_cast<DWORD>(size_a) + 0x1000u;
    replacement_size.set(size_b);

    ASSERT_EQ(memory::module_of(Address{base}).size, size_b);
    ASSERT_EQ(Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_B).size, size_b);
    EXPECT_EQ(lifecycle.generation(), generation);

    // The marker appears only after both variants occupy one base and the replacement extent matches. Earlier skips and
    // fatal assertions leave it absent.
    RecordProperty("dmk_same_base_replacement", "executed");
}

// module_of supplies no ownership reference. The owner's FreeLibrary must unmap the image despite the retained Region.
TEST_F(MemoryTest, ModuleRangeFor_ResolvingAModuleTakesNoLoaderReference)
{
    dmk_test::GenerationFixtureModule fixture(dmk_test::RTTI_FIXTURE_VARIANT_A);
    if (!fixture.ok())
    {
        GTEST_SKIP() << "the fixed-base fixture did not map";
    }

    const std::uintptr_t base = fixture.base();
    ASSERT_NE(memory::module_of(Address{base}).size, 0u);
    ASSERT_NE(Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A).size, 0u);

    fixture.release();

    EXPECT_FALSE(memory::is_module_loaded(dmk_test::RTTI_FIXTURE_VARIANT_A))
        << "resolving a module range must not pin it against its owner's unload";
    EXPECT_EQ(Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A).size, 0u);
}

// Fresh resolution must remain deterministic while the image is stable. Performance enforcement belongs to the
// stable-host benchmark route rather than a generic-runner wall-clock assertion.
TEST_F(MemoryTest, ModuleRangeFor_StableLookupIsDeterministic)
{
    const Address probe{reinterpret_cast<const void *>(&memory::module_of)};
    const Region expected = memory::module_of(probe);
    ASSERT_NE(expected.size, 0u);

    for (int i = 0; i < 64; ++i)
    {
        const Region repeated = memory::module_of(probe);
        ASSERT_EQ(repeated.base.raw(), expected.base.raw());
        ASSERT_EQ(repeated.size, expected.size);
    }
}

TEST_F(MemoryTest, OwnModuleRange_IsValid)
{
    const Region range = Region::own();
    EXPECT_NE(range.size, 0u);
    EXPECT_TRUE(range.contains(Address{reinterpret_cast<const void *>(&Region::own)}));
}

TEST_F(MemoryTest, OwnModuleRange_StableAcrossCalls)
{
    const Region a = Region::own();
    const Region b = Region::own();
    EXPECT_EQ(a.base.raw(), b.base.raw());
    EXPECT_EQ(a.end().raw(), b.end().raw());
}

TEST_F(MemoryTest, HostModuleRange_IsValid)
{
    const Region range = Region::host();
    EXPECT_NE(range.size, 0u);

    // The test executable's main() symbol lives inside the host EXE image.
    HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    EXPECT_EQ(range.base.raw(), reinterpret_cast<uintptr_t>(host));
}

TEST_F(MemoryTest, HostModuleRange_ContainsItself)
{
    // The test executable supplies its own host() range.
    const Region range = Region::host();
    ASSERT_NE(range.size, 0u);

    HMODULE host = GetModuleHandleW(nullptr);
    ASSERT_NE(host, nullptr);
    EXPECT_TRUE(range.contains(Address{reinterpret_cast<void *>(host)}));
}

TEST_F(MemoryTest, HostModuleRange_StableAcrossCalls)
{
    const Region a = Region::host();
    const Region b = Region::host();
    EXPECT_EQ(a.base.raw(), b.base.raw());
    EXPECT_EQ(a.end().raw(), b.end().raw());
}

TEST_F(MemoryTest, ModuleRangeFor_KernelModuleResolves)
{
    // kernel32.dll supplies a foreign loaded module for the range check.
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel, nullptr);

    const Region range = memory::module_of(Address{reinterpret_cast<void *>(kernel)});
    ASSERT_NE(range.size, 0u);
    EXPECT_EQ(range.base.raw(), reinterpret_cast<uintptr_t>(kernel));
}

TEST_F(MemoryTest, RegionOwn_ContainsDmkFunctionAndModuleOfAgrees)
{
    const Address fn{reinterpret_cast<const void *>(&memory::init_cache)};

    const Region own = Region::own();
    ASSERT_NE(own.size, 0u);
    EXPECT_TRUE(own.contains(fn));

    const Region module = memory::module_of(fn);
    ASSERT_NE(module.size, 0u);
    EXPECT_TRUE(module.contains(fn));
}

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    extern void (*g_module_loaded_after_reference_test_hook)() noexcept;
    extern HMODULE g_module_loaded_reference_candidate_test_override;
} // namespace DetourModKit::detail
#endif // DMK_ENABLE_TEST_SEAMS

// is_module_loaded widens the name into a std::wstring, which can throw bad_alloc. The noexcept query wraps that
// allocation and fails soft under memory pressure rather than letting the throw terminate the host.
TEST_F(MemoryTest, IsModuleLoaded_AllocFailureFailsSoftNoTerminate)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    // Control: kernel32 is always loaded, so the normal path is true.
    EXPECT_TRUE(memory::is_module_loaded("kernel32.dll"));

    bool under_oom = true;
    {
        // The first failed allocation is widen_module_name's wstring. MultiByteToWideChar uses no C++ heap. GoogleTest
        // macros stay outside the poisoned window.
        dmk_test::AllocFailScope fail{0};
        under_oom = memory::is_module_loaded("kernel32.dll");
    }
    // The widen allocation failed, so the query fails closed to false instead of terminating the noexcept host path.
    EXPECT_FALSE(under_oom);

    bool path_under_oom = true;
    {
        dmk_test::AllocFailScope fail{1};
        path_under_oom = memory::is_module_loaded("kernel32.dll", false);
    }
    EXPECT_FALSE(path_under_oom);
}

// MultiByteToWideChar accepts a signed count. A narrowed 0xFFFFFFFF becomes its NUL-terminated sentinel.
TEST_F(MemoryTest, ModuleNameLengthSeamRejectsOverIntMax)
{
    static_assert(
        DetourModKit::detail::module_name_length_fits_win32(static_cast<std::size_t>(INT_MAX)),
        "INT_MAX is the largest byte count the Win32 converter accepts"
    );
    static_assert(
        !DetourModKit::detail::module_name_length_fits_win32(static_cast<std::size_t>(INT_MAX) + 1U),
        "INT_MAX + 1 must fail the length seam"
    );

    // The raw pointer/count seam rejects before constructing a view or accessing the deliberately small buffer.
    static constexpr char SMALL_NAME[] = "kernel32.dll";
    EXPECT_TRUE(DetourModKit::detail::widen_module_name_bytes(SMALL_NAME, 0xFFFFFFFFu).empty());
}

// The view ends before the buffer's NUL. Only the viewed bytes can enter the widened module name.
TEST_F(MemoryTest, ModuleNameWidenIsBoundedToTheView)
{
    static constexpr char PADDED_NAME[] = "kernel32.dllTRAILING_GARBAGE";
    const std::string_view bounded{PADDED_NAME, 12}; // "kernel32.dll", no NUL at the view boundary
    EXPECT_EQ(DetourModKit::detail::widen_module_name(bounded), L"kernel32.dll");
    EXPECT_TRUE(memory::is_module_loaded(bounded));
    EXPECT_NE(Region::module_named(bounded).size, 0u);
    // The trailing garbage distinguishes bounded input from a NUL-terminated spelling.
    EXPECT_FALSE(memory::is_module_loaded(std::string_view{PADDED_NAME, sizeof(PADDED_NAME) - 1}));
}

TEST_F(MemoryTest, ModuleNameWidenRejectsNamesWin32WouldTruncateOrReplace)
{
    static constexpr char EMBEDDED_NUL[] = "kernel32.dll\0ignored";
    EXPECT_TRUE(
        DetourModKit::detail::widen_module_name(std::string_view{EMBEDDED_NUL, sizeof(EMBEDDED_NUL) - 1}).empty()
    );
    EXPECT_FALSE(memory::is_module_loaded(std::string_view{EMBEDDED_NUL, sizeof(EMBEDDED_NUL) - 1}));
    EXPECT_EQ(Region::module_named(std::string_view{EMBEDDED_NUL, sizeof(EMBEDDED_NUL) - 1}).size, 0u);

    static constexpr char INVALID_UTF8[] = {'k', static_cast<char>(0xFF), 'x'};
    EXPECT_TRUE(DetourModKit::detail::widen_module_name(std::string_view{INVALID_UTF8, sizeof(INVALID_UTF8)}).empty());
}

namespace
{
    namespace
    {
        std::atomic<std::uint64_t> s_module_fixture_counter{0};

        [[nodiscard]] std::uint64_t next_module_fixture_id() noexcept
        {
            return s_module_fixture_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        }

        /**
         * @brief Loads a copied DLL from an owned path with an exact character count.
         * @details The fixture reports an empty state after any setup failure.
         */
        class CopiedModuleFixture
        {
        public:
            CopiedModuleFixture(std::wstring basename, std::size_t total_path_chars) noexcept
            {
                try
                {
                    initialize(std::move(basename), total_path_chars);
                }
                catch (...)
                {
                    cleanup();
                }
            }

            ~CopiedModuleFixture() noexcept { cleanup(); }

            CopiedModuleFixture(const CopiedModuleFixture &) = delete;
            CopiedModuleFixture &operator=(const CopiedModuleFixture &) = delete;
            CopiedModuleFixture(CopiedModuleFixture &&) = delete;
            CopiedModuleFixture &operator=(CopiedModuleFixture &&) = delete;

            [[nodiscard]] bool loaded() const noexcept { return m_module != nullptr; }
            [[nodiscard]] HMODULE module() const noexcept { return m_module; }
            [[nodiscard]] std::size_t path_size() const noexcept { return m_path.size(); }
            [[nodiscard]] const std::wstring &basename() const noexcept { return m_basename; }

            void release_owner() noexcept
            {
                if (m_module != nullptr)
                {
                    (void)::FreeLibrary(m_module);
                    m_module = nullptr;
                }
            }

        private:
            void initialize(std::wstring basename, std::size_t total_path_chars)
            {
                wchar_t temp_dir[MAX_PATH] = {};
                const DWORD temp_len = ::GetTempPathW(MAX_PATH, temp_dir);
                if (temp_len == 0 || temp_len >= MAX_PATH)
                {
                    return;
                }

                m_basename = std::move(basename);
                if (m_basename.empty() || total_path_chars <= m_basename.size() + 1)
                {
                    return;
                }

                const std::wstring process_id = std::to_wstring(_getpid());
                const std::wstring fixture_id = std::to_wstring(next_module_fixture_id());
                std::wstring root =
                    L"\\\\?\\" + std::wstring{temp_dir, temp_len} + L"dmk_lp_" + process_id + L"_" + fixture_id;
                const std::size_t want_dir = total_path_chars - 1 - m_basename.size();
                if (want_dir <= root.size())
                {
                    return;
                }

                if ((want_dir - root.size()) % 65 == 1)
                {
                    root += L'z';
                }
                if (!create_directory(root))
                {
                    return;
                }

                std::wstring directory = root;
                while (directory.size() < want_dir)
                {
                    const std::size_t room = want_dir - directory.size() - 1;
                    const std::size_t segment = (room > 64) ? 64 : room;
                    if (segment == 0)
                    {
                        return;
                    }
                    directory += L'\\';
                    directory.append(segment, L'a');
                    if (!create_directory(directory))
                    {
                        return;
                    }
                }
                if (directory.size() != want_dir)
                {
                    return;
                }

                wchar_t host_path[MAX_PATH] = {};
                const DWORD host_len = ::GetModuleFileNameW(nullptr, host_path, MAX_PATH);
                if (host_len == 0 || host_len >= MAX_PATH)
                {
                    return;
                }
                std::wstring source{host_path, host_len};
                const std::size_t separator = source.find_last_of(L"\\/");
                if (separator == std::wstring::npos)
                {
                    return;
                }
                source.resize(separator + 1);
                source += L"hook_target_lib.dll";

                m_path = directory + L'\\' + m_basename;
                if (::CopyFileW(source.c_str(), m_path.c_str(), FALSE) == 0)
                {
                    m_path.clear();
                    return;
                }
                m_module = ::LoadLibraryW(m_path.c_str());
            }

            [[nodiscard]] bool create_directory(const std::wstring &path)
            {
                m_created.push_back(path);
                if (::CreateDirectoryW(path.c_str(), nullptr) != 0)
                {
                    return true;
                }
                m_created.pop_back();
                return false;
            }

            void cleanup() noexcept
            {
                if (m_module != nullptr)
                {
                    (void)::FreeLibrary(m_module);
                    m_module = nullptr;
                }
                if (!m_path.empty())
                {
                    (void)::DeleteFileW(m_path.c_str());
                    m_path.clear();
                }
                for (auto it = m_created.rbegin(); it != m_created.rend(); ++it)
                {
                    (void)::RemoveDirectoryW(it->c_str());
                }
                m_created.clear();
            }

            std::vector<std::wstring> m_created;
            std::wstring m_path;
            std::wstring m_basename;
            HMODULE m_module{nullptr};
        };

        CopiedModuleFixture *s_release_module_fixture = nullptr;

        void release_module_fixture_owner() noexcept
        {
            if (s_release_module_fixture != nullptr)
            {
                s_release_module_fixture->release_owner();
            }
        }

        class ScopedModuleReferenceRelease
        {
        public:
            explicit ScopedModuleReferenceRelease(CopiedModuleFixture &fixture) noexcept
            {
                s_release_module_fixture = &fixture;
                DetourModKit::detail::g_module_loaded_after_reference_test_hook = &release_module_fixture_owner;
            }

            ~ScopedModuleReferenceRelease() noexcept
            {
                DetourModKit::detail::g_module_loaded_after_reference_test_hook = nullptr;
                s_release_module_fixture = nullptr;
            }

            ScopedModuleReferenceRelease(const ScopedModuleReferenceRelease &) = delete;
            ScopedModuleReferenceRelease &operator=(const ScopedModuleReferenceRelease &) = delete;
            ScopedModuleReferenceRelease(ScopedModuleReferenceRelease &&) = delete;
            ScopedModuleReferenceRelease &operator=(ScopedModuleReferenceRelease &&) = delete;
        };

        class ScopedModuleCandidateOverride
        {
        public:
            explicit ScopedModuleCandidateOverride(HMODULE module) noexcept
            {
                DetourModKit::detail::g_module_loaded_reference_candidate_test_override = module;
            }

            ~ScopedModuleCandidateOverride() noexcept
            {
                DetourModKit::detail::g_module_loaded_reference_candidate_test_override = nullptr;
            }

            ScopedModuleCandidateOverride(const ScopedModuleCandidateOverride &) = delete;
            ScopedModuleCandidateOverride &operator=(const ScopedModuleCandidateOverride &) = delete;
            ScopedModuleCandidateOverride(ScopedModuleCandidateOverride &&) = delete;
            ScopedModuleCandidateOverride &operator=(ScopedModuleCandidateOverride &&) = delete;
        };

        [[nodiscard]] std::string narrow_ascii(std::wstring_view text)
        {
            std::string result;
            result.reserve(text.size());
            for (const wchar_t character : text)
            {
                result.push_back(static_cast<char>(character));
            }
            return result;
        }
    } // namespace

    TEST_F(MemoryTest, IsModuleLoadedExactCaseLongPath)
    {
        constexpr std::size_t fixture_path_chars = 384;
        const std::uint64_t fixture_id = next_module_fixture_id();
        const std::wstring basename =
            L"dmk_longpath_" + std::to_wstring(_getpid()) + L"_" + std::to_wstring(fixture_id) + L".dll";
        const CopiedModuleFixture fixture{basename, fixture_path_chars};
        if (!fixture.loaded())
        {
            GTEST_SKIP() << "the host filesystem refused a " << fixture_path_chars << "-character module path";
        }
        ASSERT_EQ(fixture.path_size(), fixture_path_chars);
        ASSERT_GT(fixture.path_size(), static_cast<std::size_t>(MAX_PATH));

        const std::string exact_name = narrow_ascii(fixture.basename());
        std::string shouted_name = exact_name;
        for (char &c : shouted_name)
        {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }

        EXPECT_TRUE(memory::is_module_loaded(exact_name, true));
        EXPECT_TRUE(memory::is_module_loaded(exact_name, false))
            << "the loaded spelling matches exactly, so the long path must not fail the query closed";
        EXPECT_TRUE(memory::is_module_loaded(shouted_name, true));
        EXPECT_FALSE(memory::is_module_loaded(shouted_name, false))
            << "a different spelling of a present module is still an exact-case miss";
        EXPECT_NE(
            memory::module_of(Address{::GetModuleHandleW(fixture.basename().c_str())}).size,
            static_cast<std::size_t>(0)
        );
    }

    TEST_F(MemoryTest, IsModuleLoadedExactCaseRetainsModuleReference)
    {
        constexpr std::size_t fixture_path_chars = 220;
        const std::uint64_t fixture_id = next_module_fixture_id();
        const std::wstring basename =
            L"dmk_module_ref_" + std::to_wstring(_getpid()) + L"_" + std::to_wstring(fixture_id) + L".dll";
        CopiedModuleFixture fixture{basename, fixture_path_chars};
        ASSERT_TRUE(fixture.loaded());
        const std::string exact_name = narrow_ascii(fixture.basename());

        {
            const ScopedModuleReferenceRelease release{fixture};
            EXPECT_TRUE(memory::is_module_loaded(exact_name, false));
        }

        EXPECT_EQ(::GetModuleHandleW(fixture.basename().c_str()), nullptr);
    }

    TEST_F(MemoryTest, IsModuleLoadedExactCaseRejectsLoaderLock)
    {
        EXPECT_TRUE(memory::is_module_loaded("kernel32.dll", true));
        const dmk_test::ForcedLoaderProbe veto;
        EXPECT_TRUE(memory::is_module_loaded("kernel32.dll", true));
        EXPECT_FALSE(memory::is_module_loaded("kernel32.dll", false));
    }

    TEST_F(MemoryTest, IsModuleLoadedExactCaseFindsEachDuplicateBasename)
    {
        constexpr std::size_t fixture_path_chars = 220;
        const std::uint64_t fixture_id = next_module_fixture_id();
        const std::string lower_name =
            "dmk_duplicate_" + std::to_string(_getpid()) + "_" + std::to_string(fixture_id) + ".dll";
        std::string upper_name = lower_name;
        for (char &character : upper_name)
        {
            character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        }

        const std::wstring lower_wide{lower_name.begin(), lower_name.end()};
        const std::wstring upper_wide{upper_name.begin(), upper_name.end()};
        const CopiedModuleFixture lower_fixture{lower_wide, fixture_path_chars};
        const CopiedModuleFixture upper_fixture{upper_wide, fixture_path_chars};
        ASSERT_TRUE(lower_fixture.loaded());
        ASSERT_TRUE(upper_fixture.loaded());
        ASSERT_NE(lower_fixture.module(), upper_fixture.module());

        {
            const ScopedModuleCandidateOverride candidate{lower_fixture.module()};
            EXPECT_TRUE(memory::is_module_loaded(upper_name, false));
        }
        {
            const ScopedModuleCandidateOverride candidate{upper_fixture.module()};
            EXPECT_TRUE(memory::is_module_loaded(lower_name, false));
        }
    }

    /// Uses the memory cache fixture for the named loader-boundary proof.
    class MemoryLoaderBoundary : public MemoryTest
    {
    };

    // [B-100] memory boundary. The Callback-safe accessors remain available under the loader lock and touch no heap.
    // The fail-closed half of the same boundary is pinned by MemoryTest.IsModuleLoadedExactCaseRejectsLoaderLock
    // and MemoryTest.InitCacheVetoedWhileRunningStaysTrue.
    TEST_F(MemoryLoaderBoundary, CallbackSafeAccessIsAllocationFree)
    {
        dmk_test::ScratchPage page;
        ASSERT_TRUE(page.ok());
        auto *const cells = static_cast<std::uint64_t *>(page.base());
        cells[0] = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&cells[4]));
        cells[4] = 0x1122334455667788ULL;

        const Address base{page.base()};
        const Address leaf_address{&cells[4]};
        std::array<std::byte, sizeof(std::uint64_t)> scratch{};
        constexpr std::ptrdiff_t chain[]{0, 0};
        const std::span<const std::ptrdiff_t> offsets{chain};

        // Measure against a live cache: the guarded accessors must stay heap-free even when the protection cache
        // is available to them.
        ASSERT_TRUE(memory::init_cache());

        // Warm every guarded route first. The MinGW engine installs its vectored handler on first use, and that
        // one-time install allocates.
        (void)memory::read<std::uint64_t>(leaf_address);
        (void)memory::read_into(base, std::span<std::byte>{scratch});
        (void)memory::write_in_place(leaf_address, std::uint64_t{1});
        (void)memory::walk(base, offsets);

        bool plausible = false;
        bool read_ok = false;
        bool read_into_ok = false;
        bool write_ok = false;
        Address walked{};
        long long allocations = -1;

        {
            const dmk_test::ForcedLoaderProbe held;

            const long long before = dmk_test::thread_new_calls();
            plausible = memory::is_plausible_ptr(base);
            read_ok = memory::read<std::uint64_t>(leaf_address).has_value();
            read_into_ok = memory::read_into(base, std::span<std::byte>{scratch}).has_value();
            write_ok = memory::write_in_place(leaf_address, std::uint64_t{7}).has_value();
            walked = memory::walk(base, offsets).value_or(Address{});
            allocations = dmk_test::thread_new_calls() - before;
        }

        EXPECT_EQ(allocations, 0LL) << "a loader-lock-safe accessor must never reach the heap";
        EXPECT_TRUE(plausible);
        EXPECT_TRUE(read_ok);
        EXPECT_TRUE(read_into_ok);
        EXPECT_TRUE(write_ok);
        EXPECT_EQ(walked, leaf_address) << "the guarded walk stays available under the loader lock";
        EXPECT_EQ(cells[4], static_cast<std::uint64_t>(7));
    }
} // namespace
