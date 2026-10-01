#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/scan.hpp"

#include "fixtures/rtti_generation_fixture.hpp"
#include "fixtures/scratch_page.hpp"

#include <windows.h>
#include "fixtures/anchor_fixture.hpp"
using namespace dmk_test::anchor_fixture;

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    extern void (*g_scan_after_byte_sweep_test_hook)() noexcept;
    extern void (*g_anchor_after_named_export_lookup_test_hook)() noexcept;
    extern void (*g_anchor_after_owner_identity_test_hook)() noexcept;
    extern void (*g_anchor_after_confirmed_owner_identity_test_hook)() noexcept;
    extern void (*g_anchor_after_witness_test_hook)() noexcept;
} // namespace DetourModKit::detail
#endif

// A resolved report carries its image, physical source, decoded operand kind, and completeness.

TEST(AnchorWitnessTest, ResolvedExportCarriesLiveImageIdentityAndSource)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok()) << "Failed to load " << ExportFixture::MODULE_NAME << ": " << GetLastError();
    ASSERT_NE(fixture.proc("compute_damage"), 0U);

    an::Anchor anchor{};
    anchor.label = "fixture.compute_damage";
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "compute_damage";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::ExportTable);
    EXPECT_EQ(result.witness.completeness, an::WitnessCompleteness::Complete);
    ASSERT_TRUE(result.witness.image.present());
    // The witness image is the identity of the module the export actually resolved in.
    EXPECT_EQ(result.witness.image, sc::image_identity(dmk::Region::module_named(ExportFixture::MODULE_NAME)));
}

TEST(AnchorWitnessTest, ManualScalarCarriesSourceButNoImage)
{
    an::Anchor anchor{};
    anchor.label = "pinned";
    anchor.kind = an::AnchorKind::Manual;
    anchor.manual_value = 0x1234;

    const an::ResolvedAnchor result = an::resolve(anchor);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::ManualPin);
    EXPECT_EQ(result.witness.completeness, an::WitnessCompleteness::Complete);
    // A Scalar is a constant, not a location, so it carries no live-image identity.
    EXPECT_FALSE(result.witness.image.present());
    EXPECT_FALSE(result.witness.evidence.present());
}

TEST(AnchorWitnessTest, CodeOperandCarriesNoContentEvidenceDespiteLocatingByBytes)
{
    // CodeOperand decodes a Scalar rather than a byte span. A content baseline cannot authorize mutation of that
    // scalar.
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0x48, 0x05, 0xF0, 0x00, 0x00, 0x00}); // add rax, 0xF0

    const sc::Candidate cands[] = {sc::Candidate::direct("add-imm", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "stride";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = cands;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
    EXPECT_EQ(result.domain, an::ResultDomain::Scalar);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::CodeOperand);
    EXPECT_FALSE(result.witness.evidence.present());
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorWitnessTest, RipGlobalReportsItsWinningStringSource)
{
    StringImage image;
    ASSERT_TRUE(image.ok());
    constexpr std::string_view literal = "AnchorWitnessStringCandidate";
    image.write_string(0x400, literal);
    image.plant_rip_load(0x100, 0x400, 0x8D);

    const sc::Candidate candidates[] = {sc::Candidate::string_xref("string", std::string{literal})};
    an::Anchor anchor{};
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;

    const an::ResolvedAnchor result = an::resolve(anchor, image.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::StringLiteral);
    // The structure rung wins this RipGlobal ladder. It supplies no matched byte span for the content gate.
    EXPECT_FALSE(result.witness.evidence.present());
}

TEST(AnchorWitnessTest, UnresolvedReportOmitsWitness)
{
    ExportFixture fixture;
    ASSERT_TRUE(fixture.ok());

    an::Anchor anchor{};
    anchor.label = "missing";
    anchor.kind = an::AnchorKind::ExportName;
    anchor.export_module = ExportFixture::MODULE_NAME;
    anchor.export_name = "this_export_does_not_exist";

    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    ASSERT_NE(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.witness.source, an::PhysicalSource::None);
    EXPECT_EQ(result.witness.completeness, an::WitnessCompleteness::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorWitnessTest, PhysicalSourceToStringMapsEverySource)
{
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::None), "None");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::ByteSignature), "ByteSignature");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::StringLiteral), "StringLiteral");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::TypeIdentity), "TypeIdentity");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::ExportTable), "ExportTable");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::CodeOperand), "CodeOperand");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::ManualPin), "ManualPin");
    EXPECT_EQ(an::physical_source_to_string(an::PhysicalSource::Corroborated), "Corroborated");
    EXPECT_EQ(an::physical_source_to_string(static_cast<an::PhysicalSource>(0xFF)), "Unknown");
}

// The fixture replaces the module at its own base during resolve. The published identity cannot certify evidence from
// the prior image.

namespace
{
    dmk_test::SameBaseSwap *s_anchor_swap = nullptr;
    bool s_anchor_swap_happened = false;

    [[nodiscard]] bool try_swap_anchor_fixture() noexcept
    {
        if (s_anchor_swap == nullptr)
        {
            return false;
        }
        try
        {
            return s_anchor_swap->swap_to_b();
        }
        catch (...)
        {
            return false;
        }
    }

    // The validator accepts the value and replaces its image before the report commits.
    bool swap_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_anchor_swap != nullptr && !s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
        return true;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    void swap_after_discovery_sweep() noexcept
    {
        DetourModKit::detail::g_scan_after_byte_sweep_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedDiscoverySweepHook
    {
    public:
        ScopedDiscoverySweepHook() noexcept
        {
            DetourModKit::detail::g_scan_after_byte_sweep_test_hook = &swap_after_discovery_sweep;
        }

        ~ScopedDiscoverySweepHook() noexcept { DetourModKit::detail::g_scan_after_byte_sweep_test_hook = nullptr; }

        ScopedDiscoverySweepHook(const ScopedDiscoverySweepHook &) = delete;
        ScopedDiscoverySweepHook &operator=(const ScopedDiscoverySweepHook &) = delete;
    };

    void swap_after_named_export_lookup() noexcept
    {
        DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedNamedExportLookupHook
    {
    public:
        ScopedNamedExportLookupHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook = &swap_after_named_export_lookup;
        }

        ~ScopedNamedExportLookupHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook = nullptr;
        }

        ScopedNamedExportLookupHook(const ScopedNamedExportLookupHook &) = delete;
        ScopedNamedExportLookupHook &operator=(const ScopedNamedExportLookupHook &) = delete;
    };

    void swap_between_owner_identity_samples() noexcept
    {
        DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedOwnerIdentityHook
    {
    public:
        ScopedOwnerIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_owner_identity_test_hook = &swap_between_owner_identity_samples;
        }

        ~ScopedOwnerIdentityHook() noexcept { DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr; }

        ScopedOwnerIdentityHook(const ScopedOwnerIdentityHook &) = delete;
        ScopedOwnerIdentityHook &operator=(const ScopedOwnerIdentityHook &) = delete;
    };

    void swap_after_witness_construction() noexcept
    {
        DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr;
        if (!s_anchor_swap_happened)
        {
            s_anchor_swap_happened = try_swap_anchor_fixture();
        }
    }

    class ScopedWitnessHook
    {
    public:
        ScopedWitnessHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_witness_test_hook = &swap_after_witness_construction;
        }

        ~ScopedWitnessHook() noexcept { DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr; }

        ScopedWitnessHook(const ScopedWitnessHook &) = delete;
        ScopedWitnessHook &operator=(const ScopedWitnessHook &) = delete;
    };
#endif

    dmk_test::GenerationFixtureModule *s_private_replacement_module = nullptr;
    const std::byte *s_private_replacement_header = nullptr;
    std::size_t s_private_replacement_header_size = 0;
    std::uintptr_t s_private_replacement_base = 0;
    std::size_t s_private_replacement_image_size = 0;
    void *s_private_replacement_mapping = nullptr;
    HMODULE s_private_replacement_restored_module = nullptr;
    bool s_private_replacement_happened = false;
    bool s_private_replacement_restored = false;

    bool replace_with_private_image_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_private_replacement_module == nullptr || s_private_replacement_happened)
        {
            return true;
        }
        try
        {
            s_private_replacement_module->release();
        }
        catch (...)
        {
            return true;
        }
        void *const mapping = ::VirtualAlloc(
            reinterpret_cast<void *>(s_private_replacement_base),
            s_private_replacement_image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (reinterpret_cast<std::uintptr_t>(mapping) != s_private_replacement_base)
        {
            if (mapping != nullptr)
            {
                (void)::VirtualFree(mapping, 0, MEM_RELEASE);
            }
            return true;
        }
        std::memcpy(mapping, s_private_replacement_header, s_private_replacement_header_size);
        s_private_replacement_mapping = mapping;
        s_private_replacement_happened = true;
        return true;
    }

    class ScopedPrivateImageReplacement
    {
    public:
        ScopedPrivateImageReplacement(
            dmk_test::GenerationFixtureModule &module,
            dmk::Region image,
            std::span<const std::byte> header
        ) noexcept
        {
            s_private_replacement_module = &module;
            s_private_replacement_header = header.data();
            s_private_replacement_header_size = header.size();
            s_private_replacement_base = image.base.raw();
            s_private_replacement_image_size = image.size;
            s_private_replacement_mapping = nullptr;
            s_private_replacement_restored_module = nullptr;
            s_private_replacement_happened = false;
            s_private_replacement_restored = false;
        }

        ~ScopedPrivateImageReplacement() noexcept
        {
            s_private_replacement_module = nullptr;
            s_private_replacement_header = nullptr;
            s_private_replacement_header_size = 0;
            s_private_replacement_base = 0;
            s_private_replacement_image_size = 0;
            if (s_private_replacement_restored_module != nullptr)
            {
                ::FreeLibrary(s_private_replacement_restored_module);
                s_private_replacement_restored_module = nullptr;
            }
            if (s_private_replacement_mapping != nullptr)
            {
                (void)::VirtualFree(s_private_replacement_mapping, 0, MEM_RELEASE);
                s_private_replacement_mapping = nullptr;
            }
            s_private_replacement_happened = false;
            s_private_replacement_restored = false;
        }

        ScopedPrivateImageReplacement(const ScopedPrivateImageReplacement &) = delete;
        ScopedPrivateImageReplacement &operator=(const ScopedPrivateImageReplacement &) = delete;

        [[nodiscard]] bool happened() const noexcept { return s_private_replacement_happened; }
        [[nodiscard]] bool restored() const noexcept { return s_private_replacement_restored; }
    };

#if defined(DMK_ENABLE_TEST_SEAMS)
    void replace_with_private_image_during_owner_identity() noexcept
    {
        DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr;
        (void)replace_with_private_image_then_accept(0, nullptr);
    }

    class ScopedPrivateOwnerIdentityHook
    {
    public:
        ScopedPrivateOwnerIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_owner_identity_test_hook =
                &replace_with_private_image_during_owner_identity;
        }

        ~ScopedPrivateOwnerIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_owner_identity_test_hook = nullptr;
        }

        ScopedPrivateOwnerIdentityHook(const ScopedPrivateOwnerIdentityHook &) = delete;
        ScopedPrivateOwnerIdentityHook &operator=(const ScopedPrivateOwnerIdentityHook &) = delete;
    };

    void restore_image_after_confirmed_identity() noexcept
    {
        DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        if (s_private_replacement_mapping == nullptr || !::VirtualFree(s_private_replacement_mapping, 0, MEM_RELEASE))
        {
            return;
        }
        s_private_replacement_mapping = nullptr;
        HMODULE const module = ::LoadLibraryA(dmk_test::RTTI_FIXTURE_VARIANT_A);
        if (reinterpret_cast<std::uintptr_t>(module) != s_private_replacement_base)
        {
            if (module != nullptr)
            {
                ::FreeLibrary(module);
            }
            return;
        }
        s_private_replacement_restored_module = module;
        s_private_replacement_restored = true;
    }

    class ScopedImageRestoreAfterConfirmedIdentityHook
    {
    public:
        ScopedImageRestoreAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook =
                &restore_image_after_confirmed_identity;
        }

        ~ScopedImageRestoreAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        }

        ScopedImageRestoreAfterConfirmedIdentityHook(const ScopedImageRestoreAfterConfirmedIdentityHook &) = delete;
        ScopedImageRestoreAfterConfirmedIdentityHook &
        operator=(const ScopedImageRestoreAfterConfirmedIdentityHook &) = delete;
    };

    void replace_with_private_image_after_confirmed_identity() noexcept
    {
        DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        (void)replace_with_private_image_then_accept(0, nullptr);
    }

    class ScopedPrivateAfterConfirmedIdentityHook
    {
    public:
        ScopedPrivateAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook =
                &replace_with_private_image_after_confirmed_identity;
        }

        ~ScopedPrivateAfterConfirmedIdentityHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook = nullptr;
        }

        ScopedPrivateAfterConfirmedIdentityHook(const ScopedPrivateAfterConfirmedIdentityHook &) = delete;
        ScopedPrivateAfterConfirmedIdentityHook &operator=(const ScopedPrivateAfterConfirmedIdentityHook &) = delete;
    };

    class ScopedWitnessIdentityMutation;
    ScopedWitnessIdentityMutation *s_witness_identity_mutation = nullptr;

    class ScopedWitnessIdentityMutation
    {
    public:
        explicit ScopedWitnessIdentityMutation(dmk::Region image) noexcept
        {
            auto *const dos = image.base.as<IMAGE_DOS_HEADER *>();
            if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(image.base.raw() + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.NumberOfSections == 0)
            {
                return;
            }
            m_characteristics = &IMAGE_FIRST_SECTION(nt)->Characteristics;
            if (!::VirtualProtect(m_characteristics, sizeof(*m_characteristics), PAGE_READWRITE, &m_old_protection))
            {
                m_characteristics = nullptr;
                return;
            }
            m_original_characteristics = *m_characteristics;
            m_original_identity = sc::image_identity(image);
            *m_characteristics = m_original_characteristics ^ IMAGE_SCN_MEM_WRITE;
            m_changed_identity = sc::image_identity(image);
            *m_characteristics = m_original_characteristics;
            s_witness_identity_mutation = this;
        }

        ~ScopedWitnessIdentityMutation() noexcept
        {
            restore();
            if (m_characteristics != nullptr)
            {
                DWORD ignored = 0;
                (void)::VirtualProtect(m_characteristics, sizeof(*m_characteristics), m_old_protection, &ignored);
            }
            if (s_witness_identity_mutation == this)
            {
                s_witness_identity_mutation = nullptr;
            }
        }

        ScopedWitnessIdentityMutation(const ScopedWitnessIdentityMutation &) = delete;
        ScopedWitnessIdentityMutation &operator=(const ScopedWitnessIdentityMutation &) = delete;

        [[nodiscard]] bool ok() const noexcept
        {
            return m_characteristics != nullptr && m_original_identity.present() && m_changed_identity.present() &&
                   m_original_identity != m_changed_identity;
        }
        [[nodiscard]] bool mutated() const noexcept { return m_mutated; }
        [[nodiscard]] bool restored() const noexcept { return m_restored; }
        [[nodiscard]] sc::ImageIdentity original_identity() const noexcept { return m_original_identity; }

        void mutate() noexcept
        {
            if (m_characteristics != nullptr && !m_mutated)
            {
                *m_characteristics = m_original_characteristics ^ IMAGE_SCN_MEM_WRITE;
                m_mutated = true;
                m_restored = false;
            }
        }

        void restore() noexcept
        {
            if (m_characteristics != nullptr && m_mutated && !m_restored)
            {
                *m_characteristics = m_original_characteristics;
                m_restored = true;
            }
        }

    private:
        DWORD *m_characteristics{nullptr};
        DWORD m_original_characteristics{0};
        DWORD m_old_protection{0};
        sc::ImageIdentity m_original_identity{};
        sc::ImageIdentity m_changed_identity{};
        bool m_mutated{false};
        bool m_restored{false};
    };

    bool mutate_identity_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_witness_identity_mutation != nullptr)
        {
            s_witness_identity_mutation->mutate();
        }
        return true;
    }

    void restore_identity_after_witness() noexcept
    {
        DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr;
        if (s_witness_identity_mutation != nullptr)
        {
            s_witness_identity_mutation->restore();
        }
    }

    class ScopedWitnessIdentityRestoreHook
    {
    public:
        ScopedWitnessIdentityRestoreHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_witness_test_hook = &restore_identity_after_witness;
        }

        ~ScopedWitnessIdentityRestoreHook() noexcept
        {
            DetourModKit::detail::g_anchor_after_witness_test_hook = nullptr;
        }

        ScopedWitnessIdentityRestoreHook(const ScopedWitnessIdentityRestoreHook &) = delete;
        ScopedWitnessIdentityRestoreHook &operator=(const ScopedWitnessIdentityRestoreHook &) = delete;
    };
#endif

    void *s_synthetic_image_mapping = nullptr;
    HMODULE s_synthetic_image_module = nullptr;
    std::uintptr_t s_synthetic_image_base = 0;
    bool s_synthetic_image_replacement_happened = false;

    bool replace_synthetic_with_image_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_synthetic_image_mapping == nullptr || s_synthetic_image_replacement_happened)
        {
            return true;
        }
        if (!::VirtualFree(s_synthetic_image_mapping, 0, MEM_RELEASE))
        {
            return true;
        }
        s_synthetic_image_mapping = nullptr;
        HMODULE const module = ::LoadLibraryA(dmk_test::RTTI_FIXTURE_VARIANT_A);
        if (reinterpret_cast<std::uintptr_t>(module) != s_synthetic_image_base)
        {
            if (module != nullptr)
            {
                (void)::FreeLibrary(module);
            }
            return true;
        }
        s_synthetic_image_module = module;
        s_synthetic_image_replacement_happened = true;
        return true;
    }

    class ScopedSyntheticToImageReplacement
    {
    public:
        explicit ScopedSyntheticToImageReplacement(std::uintptr_t base, bool reserved_prefix = false) noexcept
        {
            const std::size_t allocation_size = reserved_prefix ? ScratchPage::PAGE_SIZE * 2 : ScratchPage::PAGE_SIZE;
            const DWORD allocation_type = reserved_prefix ? MEM_RESERVE : MEM_COMMIT | MEM_RESERVE;
            const DWORD protection = reserved_prefix ? PAGE_NOACCESS : PAGE_EXECUTE_READWRITE;
            void *const mapping =
                ::VirtualAlloc(reinterpret_cast<void *>(base), allocation_size, allocation_type, protection);
            if (reinterpret_cast<std::uintptr_t>(mapping) != base)
            {
                if (mapping != nullptr)
                {
                    (void)::VirtualFree(mapping, 0, MEM_RELEASE);
                }
                return;
            }
            if (reserved_prefix)
            {
                void *const committed = ::VirtualAlloc(
                    reinterpret_cast<void *>(base + ScratchPage::PAGE_SIZE),
                    ScratchPage::PAGE_SIZE,
                    MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE
                );
                if (reinterpret_cast<std::uintptr_t>(committed) != base + ScratchPage::PAGE_SIZE)
                {
                    (void)::VirtualFree(mapping, 0, MEM_RELEASE);
                    return;
                }
            }
            s_synthetic_image_mapping = mapping;
            s_synthetic_image_module = nullptr;
            s_synthetic_image_base = base;
            s_synthetic_image_replacement_happened = false;
            m_size = allocation_size;
        }

        ~ScopedSyntheticToImageReplacement() noexcept
        {
            if (s_synthetic_image_module != nullptr)
            {
                (void)::FreeLibrary(s_synthetic_image_module);
                s_synthetic_image_module = nullptr;
            }
            if (s_synthetic_image_mapping != nullptr)
            {
                (void)::VirtualFree(s_synthetic_image_mapping, 0, MEM_RELEASE);
                s_synthetic_image_mapping = nullptr;
            }
            s_synthetic_image_base = 0;
            s_synthetic_image_replacement_happened = false;
            m_size = 0;
        }

        ScopedSyntheticToImageReplacement(const ScopedSyntheticToImageReplacement &) = delete;
        ScopedSyntheticToImageReplacement &operator=(const ScopedSyntheticToImageReplacement &) = delete;

        [[nodiscard]] bool ok() const noexcept { return s_synthetic_image_mapping != nullptr; }
        [[nodiscard]] bool happened() const noexcept { return s_synthetic_image_replacement_happened; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept
        {
            return s_synthetic_image_base + offset;
        }
        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{s_synthetic_image_base}, m_size};
        }
        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(reinterpret_cast<void *>(address(offset)), bytes.data(), bytes.size());
        }

    private:
        std::size_t m_size{0};
    };

    void *s_split_original_mapping = nullptr;
    void *s_split_first_mapping = nullptr;
    void *s_split_second_mapping = nullptr;
    std::uintptr_t s_split_base = 0;
    std::size_t s_split_granularity = 0;
    const std::uint8_t *s_split_marker = nullptr;
    std::size_t s_split_marker_size = 0;
    bool s_split_happened = false;
    constexpr std::size_t SPLIT_MARKER_OFFSET = 0x100;

    bool split_scope_allocation_then_accept(std::int64_t, const void *) noexcept
    {
        if (s_split_original_mapping == nullptr || s_split_happened)
        {
            return true;
        }
        if (!::VirtualFree(s_split_original_mapping, 0, MEM_RELEASE))
        {
            return true;
        }
        s_split_original_mapping = nullptr;
        s_split_first_mapping = ::VirtualAlloc(
            reinterpret_cast<void *>(s_split_base),
            s_split_granularity,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        s_split_second_mapping = ::VirtualAlloc(
            reinterpret_cast<void *>(s_split_base + s_split_granularity),
            s_split_granularity,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (reinterpret_cast<std::uintptr_t>(s_split_first_mapping) != s_split_base ||
            reinterpret_cast<std::uintptr_t>(s_split_second_mapping) != s_split_base + s_split_granularity)
        {
            return true;
        }
        std::memcpy(reinterpret_cast<void *>(s_split_base + SPLIT_MARKER_OFFSET), s_split_marker, s_split_marker_size);
        std::memcpy(
            reinterpret_cast<void *>(s_split_base + s_split_granularity + SPLIT_MARKER_OFFSET),
            s_split_marker,
            s_split_marker_size
        );
        s_split_happened = true;
        return true;
    }

    class ScopedAllocationSplit
    {
    public:
        ScopedAllocationSplit() noexcept
        {
            SYSTEM_INFO system_info{};
            ::GetSystemInfo(&system_info);
            s_split_granularity = system_info.dwAllocationGranularity;
            s_split_original_mapping =
                ::VirtualAlloc(nullptr, s_split_granularity * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            s_split_base = reinterpret_cast<std::uintptr_t>(s_split_original_mapping);
            s_split_first_mapping = nullptr;
            s_split_second_mapping = nullptr;
            s_split_marker = nullptr;
            s_split_marker_size = 0;
            s_split_happened = false;
        }

        ~ScopedAllocationSplit() noexcept
        {
            if (s_split_original_mapping != nullptr)
            {
                (void)::VirtualFree(s_split_original_mapping, 0, MEM_RELEASE);
            }
            if (s_split_first_mapping != nullptr)
            {
                (void)::VirtualFree(s_split_first_mapping, 0, MEM_RELEASE);
            }
            if (s_split_second_mapping != nullptr)
            {
                (void)::VirtualFree(s_split_second_mapping, 0, MEM_RELEASE);
            }
            s_split_original_mapping = nullptr;
            s_split_first_mapping = nullptr;
            s_split_second_mapping = nullptr;
            s_split_base = 0;
            s_split_granularity = 0;
            s_split_marker = nullptr;
            s_split_marker_size = 0;
            s_split_happened = false;
        }

        ScopedAllocationSplit(const ScopedAllocationSplit &) = delete;
        ScopedAllocationSplit &operator=(const ScopedAllocationSplit &) = delete;

        [[nodiscard]] bool ok() const noexcept
        {
            return s_split_original_mapping != nullptr && s_split_granularity != 0;
        }
        [[nodiscard]] bool happened() const noexcept { return s_split_happened; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept { return s_split_base + offset; }
        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{s_split_base}, s_split_granularity * 2};
        }
        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(reinterpret_cast<void *>(address(offset)), bytes.data(), bytes.size());
            s_split_marker = bytes.data();
            s_split_marker_size = bytes.size();
        }
    };

    class ManyRegionScope
    {
    public:
        ManyRegionScope() noexcept
        {
            SYSTEM_INFO system_info{};
            ::GetSystemInfo(&system_info);
            m_page_size = system_info.dwPageSize;
            m_size = m_page_size * REGION_COUNT;
            m_base = static_cast<std::byte *>(
                ::VirtualAlloc(nullptr, m_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            );
            if (m_base == nullptr)
            {
                return;
            }
            for (std::size_t i = 1; i < REGION_COUNT; i += 2)
            {
                DWORD old_protection = 0;
                if (!::VirtualProtect(m_base + i * m_page_size, m_page_size, PAGE_READWRITE, &old_protection))
                {
                    (void)::VirtualFree(m_base, 0, MEM_RELEASE);
                    m_base = nullptr;
                    m_page_size = 0;
                    m_size = 0;
                    return;
                }
            }
        }

        ~ManyRegionScope() noexcept
        {
            if (m_base != nullptr)
            {
                (void)::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        ManyRegionScope(const ManyRegionScope &) = delete;
        ManyRegionScope &operator=(const ManyRegionScope &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::size_t page_size() const noexcept { return m_page_size; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base + offset);
        }
        [[nodiscard]] dmk::Region range() const noexcept
        {
            return dmk::Region{dmk::Address{reinterpret_cast<std::uintptr_t>(m_base)}, m_size};
        }
        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(m_base + offset, bytes.data(), bytes.size());
        }

    private:
        static constexpr std::size_t REGION_COUNT = 66;

        std::byte *m_base{nullptr};
        std::size_t m_page_size{0};
        std::size_t m_size{0};
    };

    bool accept_any(std::int64_t, const void *) noexcept
    {
        return true;
    }

    // The fixture module's own exported entry point, resolvable by name from an explicit export module.
    constexpr const char *FIXTURE_EXPORT = "dmk_rtti_fixture_vtable";

    [[nodiscard]] an::Anchor fixture_export_anchor() noexcept
    {
        an::Anchor anchor{};
        anchor.label = "fixture.export";
        anchor.kind = an::AnchorKind::ExportName;
        anchor.export_module = dmk_test::RTTI_FIXTURE_VARIANT_A;
        anchor.export_name = FIXTURE_EXPORT;
        return anchor;
    }

    constexpr std::size_t TRANSACTION_MARKER_BYTES = 32;
    constexpr std::size_t TRANSACTION_MARKER_OFFSET = 0x100;
    constexpr std::uintptr_t TRANSACTION_PAGE_GAP = 0x20000;

    class FixedExecutablePage
    {
    public:
        explicit FixedExecutablePage(std::uintptr_t requested) noexcept
        {
            m_base = static_cast<std::uint8_t *>(::VirtualAlloc(
                reinterpret_cast<void *>(requested),
                ScratchPage::PAGE_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ));
            if (reinterpret_cast<std::uintptr_t>(m_base) != requested)
            {
                if (m_base != nullptr)
                {
                    ::VirtualFree(m_base, 0, MEM_RELEASE);
                }
                m_base = nullptr;
            }
            if (m_base != nullptr)
            {
                std::memset(m_base, 0xCC, ScratchPage::PAGE_SIZE);
            }
        }

        ~FixedExecutablePage() noexcept
        {
            if (m_base != nullptr)
            {
                ::VirtualFree(m_base, 0, MEM_RELEASE);
            }
        }

        FixedExecutablePage(const FixedExecutablePage &) = delete;
        FixedExecutablePage &operator=(const FixedExecutablePage &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_base != nullptr; }
        [[nodiscard]] std::uintptr_t address(std::size_t offset = 0) const noexcept
        {
            return reinterpret_cast<std::uintptr_t>(m_base) + offset;
        }

        void put(std::size_t offset, std::span<const std::uint8_t> bytes) noexcept
        {
            std::memcpy(m_base + offset, bytes.data(), bytes.size());
        }

    private:
        std::uint8_t *m_base{nullptr};
    };

    [[nodiscard]] std::array<std::uint8_t, TRANSACTION_MARKER_BYTES> transaction_marker(std::uintptr_t seed) noexcept
    {
        std::array<std::uint8_t, TRANSACTION_MARKER_BYTES> bytes{};
        std::uint64_t state = static_cast<std::uint64_t>(seed) ^ 0xD4E12C77A51B9F03ULL;
        if (state == 0)
        {
            state = 1;
        }
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes[i] = static_cast<std::uint8_t>(state >> 24);
        }
        return bytes;
    }

    [[nodiscard]] std::string aob_for_bytes(std::span<const std::uint8_t> bytes)
    {
        constexpr char HEX[] = "0123456789ABCDEF";
        std::string dsl;
        dsl.reserve(bytes.size() * 3);
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            if (i != 0)
            {
                dsl.push_back(' ');
            }
            dsl.push_back(HEX[bytes[i] >> 4]);
            dsl.push_back(HEX[bytes[i] & 0x0F]);
        }
        return dsl;
    }

    [[nodiscard]] dmk::Region transaction_scope(const FixedExecutablePage &page, std::uintptr_t target) noexcept
    {
        return dmk::Region{dmk::Address{page.address()}, static_cast<std::size_t>(target - page.address() + 1)};
    }

    [[nodiscard]] std::ptrdiff_t target_delta(std::uintptr_t source, std::uintptr_t target) noexcept
    {
        if (target >= source)
        {
            return static_cast<std::ptrdiff_t>(target - source);
        }
        return -static_cast<std::ptrdiff_t>(source - target);
    }

    class ScopedMissingModuleRange
    {
    public:
        explicit ScopedMissingModuleRange(std::uintptr_t module_base) noexcept
        {
            auto *const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(module_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(module_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return;
            }
            m_image_size = &nt->OptionalHeader.SizeOfImage;
            if (!::VirtualProtect(m_image_size, sizeof(*m_image_size), PAGE_READWRITE, &m_old_protection))
            {
                m_image_size = nullptr;
                return;
            }
            m_original = *m_image_size;
            *m_image_size = 0;
        }

        ~ScopedMissingModuleRange() noexcept
        {
            if (m_image_size != nullptr)
            {
                *m_image_size = m_original;
                DWORD ignored = 0;
                (void)::VirtualProtect(m_image_size, sizeof(*m_image_size), m_old_protection, &ignored);
            }
        }

        ScopedMissingModuleRange(const ScopedMissingModuleRange &) = delete;
        ScopedMissingModuleRange &operator=(const ScopedMissingModuleRange &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_image_size != nullptr && m_original != 0; }

    private:
        DWORD *m_image_size{nullptr};
        DWORD m_original{0};
        DWORD m_old_protection{0};
    };

    class ScopedMissingImageIdentity
    {
    public:
        explicit ScopedMissingImageIdentity(std::uintptr_t module_base) noexcept
        {
            auto *const dos = reinterpret_cast<IMAGE_DOS_HEADER *>(module_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            {
                return;
            }
            auto *const nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(module_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return;
            }
            m_section_count = &nt->FileHeader.NumberOfSections;
            if (!::VirtualProtect(m_section_count, sizeof(*m_section_count), PAGE_READWRITE, &m_old_protection))
            {
                m_section_count = nullptr;
                return;
            }
            m_original = *m_section_count;
            *m_section_count = 0;
        }

        ~ScopedMissingImageIdentity() noexcept
        {
            if (m_section_count != nullptr)
            {
                *m_section_count = m_original;
                DWORD ignored = 0;
                (void)::VirtualProtect(m_section_count, sizeof(*m_section_count), m_old_protection, &ignored);
            }
        }

        ScopedMissingImageIdentity(const ScopedMissingImageIdentity &) = delete;
        ScopedMissingImageIdentity &operator=(const ScopedMissingImageIdentity &) = delete;

        [[nodiscard]] bool ok() const noexcept { return m_section_count != nullptr && m_original != 0; }

    private:
        WORD *m_section_count{nullptr};
        WORD m_original{0};
        DWORD m_old_protection{0};
    };
} // anonymous namespace

TEST(AnchorTrustTransactionTest, ImageMappingWithUnreadableExtentFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    const std::uintptr_t target = module.prepare();
    ASSERT_NE(target, 0U) << "variant A could not lay down its RTTI graph";
    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(scope.base.raw(), 0U);
    const std::uintptr_t marker_address = module.table();
    const auto marker = transaction_marker(target ^ marker_address ^ ::GetCurrentProcessId());
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(marker_address),
            marker.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(marker_address), marker.data(), marker.size());
    const sc::Candidate candidates[] = {
        sc::Candidate::direct("missing-module-range", aob(aob_for_bytes(marker)), target_delta(marker_address, target))
    };

    an::Anchor anchor{};
    anchor.label = "fixture.missing.range";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;

    const ScopedMissingModuleRange missing_range(module.base());
    ASSERT_TRUE(missing_range.ok()) << "fixture SizeOfImage could not be made invalid";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(target), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    ASSERT_EQ(memory_info.Type, static_cast<DWORD>(MEM_IMAGE));
    ASSERT_FALSE(sc::image_identity(scope).present()) << "the unreadable-extent premise was not established";

    const an::ResolvedAnchor result = an::resolve(anchor, scope);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ExplicitExportModuleReplacementFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    an::Anchor anchor = fixture_export_anchor();
    anchor.validator = &swap_then_accept;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(anchor, dmk::Region::host());
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present()) << "a refused resolve must publish no witness";
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(AnchorTrustTransactionTest, NamedExportReplacementBeforeOwnerCaptureFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedNamedExportLookupHook hook;
        result = an::resolve(fixture_export_anchor(), dmk::Region::host());
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "the named image was not replaced before its owner capture";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementBetweenOwnerIdentitySamplesFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);

    const std::uintptr_t instruction_address = swap.module().table();
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            instruction.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {sc::Candidate::direct("identity-sample-swap", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.identity.sample.swap";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;
    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedOwnerIdentityHook hook;
        result = an::resolve(anchor, fixture);
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "the image did not move between the two identity samples";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementAfterWitnessConstructionFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);

    an::Anchor anchor = fixture_export_anchor();
    anchor.export_module = {};
    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedWitnessHook hook;
        result = an::resolve(anchor, fixture);
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "the image did not move after witness construction";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}
#endif

TEST(AnchorTrustTransactionTest, ModuleBackedEvidenceWithoutAnIdentityFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    const ScopedMissingImageIdentity missing_identity(module.base());
    ASSERT_TRUE(missing_identity.ok()) << "fixture PE header could not be made writable";
    ASSERT_FALSE(sc::image_identity(fixture).present()) << "the identity-failure premise was not established";
    ASSERT_TRUE(sc::resolve_export(FIXTURE_EXPORT, fixture).has_value())
        << "the export backend must still resolve while only the identity section count is invalid";

    const an::ResolvedAnchor result = an::resolve(fixture_export_anchor(), dmk::Region::host());
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ImageReplacementByPrivatePeCopyFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ASSERT_GE(fixture.size, ScratchPage::PAGE_SIZE);
    const sc::ImageIdentity original_identity = sc::image_identity(fixture);
    ASSERT_TRUE(original_identity.present());
    std::array<std::byte, ScratchPage::PAGE_SIZE> header{};
    std::memcpy(header.data(), reinterpret_cast<const void *>(fixture.base.raw()), header.size());

    an::Anchor anchor = fixture_export_anchor();
    anchor.export_module = {};
    anchor.validator = &replace_with_private_image_then_accept;
    ScopedPrivateImageReplacement replacement(module, fixture, header);
    const an::ResolvedAnchor result = an::resolve(anchor, fixture);

    ASSERT_TRUE(replacement.happened()) << "the loader image was not replaced by a private mapping at the same base";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(fixture.base.raw()), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    EXPECT_EQ(sc::image_identity(dmk::Region{fixture.base, 1}), original_identity)
        << "the private replacement must retain the PE identity that defeated an identity-only recheck";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(AnchorTrustTransactionTest, PrivateReplacementInsideOwnerIdentityBracketFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ASSERT_GE(fixture.size, ScratchPage::PAGE_SIZE);
    const sc::ImageIdentity original_identity = sc::image_identity(fixture);
    ASSERT_TRUE(original_identity.present());
    std::array<std::byte, ScratchPage::PAGE_SIZE> header{};
    std::memcpy(header.data(), reinterpret_cast<const void *>(fixture.base.raw()), header.size());

    const std::uintptr_t instruction_address = module.table();
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            instruction.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {sc::Candidate::direct("private-during-identity", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.private.identity.bracket";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    ScopedPrivateImageReplacement replacement(module, fixture, header);
    an::ResolvedAnchor result{};
    {
        ScopedPrivateOwnerIdentityHook hook;
        ScopedImageRestoreAfterConfirmedIdentityHook restore_hook;
        result = an::resolve(anchor, fixture);
    }

    ASSERT_TRUE(replacement.happened()) << "the image was not replaced inside the owner-identity bracket";
    EXPECT_FALSE(replacement.restored()) << "the middle mapping check did not stop before the restore seam";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(fixture.base.raw()), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    EXPECT_EQ(sc::image_identity(dmk::Region{fixture.base, 1}), original_identity)
        << "the private clone must remain identity-equal so only the post-read mapping check can reject it";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, PrivateReplacementAfterConfirmedIdentityFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ASSERT_GE(fixture.size, ScratchPage::PAGE_SIZE);
    const sc::ImageIdentity original_identity = sc::image_identity(fixture);
    ASSERT_TRUE(original_identity.present());
    std::array<std::byte, ScratchPage::PAGE_SIZE> header{};
    std::memcpy(header.data(), reinterpret_cast<const void *>(fixture.base.raw()), header.size());

    const std::uintptr_t instruction_address = module.table();
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            instruction.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {
        sc::Candidate::direct("private-after-confirmed-identity", aob("48 05 F0 00 00 00"))
    };
    an::Anchor anchor{};
    anchor.label = "fixture.private.after.confirmed.identity";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    ScopedPrivateImageReplacement replacement(module, fixture, header);
    an::ResolvedAnchor result{};
    {
        ScopedPrivateAfterConfirmedIdentityHook hook;
        result = an::resolve(anchor, fixture);
    }

    ASSERT_TRUE(replacement.happened()) << "the image was not replaced after the confirmed identity sample";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(fixture.base.raw()), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    EXPECT_EQ(sc::image_identity(dmk::Region{fixture.base, 1}), original_identity)
        << "the private clone must remain identity-equal so only the final mapping check can reject it";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, WitnessCopiesCapturedIdentityInsteadOfResampling)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region fixture = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(fixture.base.raw(), 0U);
    ScopedWitnessIdentityMutation mutation(fixture);
    ASSERT_TRUE(mutation.ok()) << "changing the section header did not produce a distinct live identity";

    an::Anchor anchor = fixture_export_anchor();
    anchor.export_module = {};
    anchor.validator = &mutate_identity_then_accept;
    an::ResolvedAnchor result{};
    {
        ScopedWitnessIdentityRestoreHook hook;
        result = an::resolve(anchor, fixture);
    }

    ASSERT_TRUE(mutation.mutated()) << "the validator did not change the identity after owner capture";
    ASSERT_TRUE(mutation.restored()) << "the post-witness seam did not restore the accepted identity";
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    ASSERT_TRUE(result.witness.image.present());
    EXPECT_EQ(result.witness.image, mutation.original_identity());
    EXPECT_EQ(sc::image_identity(fixture), mutation.original_identity());
}
#endif

TEST(AnchorTrustTransactionTest, SyntheticReplacementByImageFailsClosed)
{
    std::uintptr_t preferred_base = 0;
    {
        dmk_test::GenerationFixtureModule probe(dmk_test::RTTI_FIXTURE_VARIANT_A);
        ASSERT_TRUE(probe.ok()) << "variant A did not map while discovering its fixed base";
        preferred_base = probe.base();
        probe.release();
    }
    ASSERT_NE(preferred_base, 0U);

    ScopedSyntheticToImageReplacement replacement(preferred_base);
    ASSERT_TRUE(replacement.ok()) << "a synthetic page could not reserve the fixture's fixed base";
    const auto marker = transaction_marker(preferred_base ^ ::GetCurrentProcessId());
    replacement.put(TRANSACTION_MARKER_OFFSET, marker);
    const sc::Candidate candidates[] = {sc::Candidate::direct("synthetic-to-image", aob(aob_for_bytes(marker)))};
    an::Anchor anchor{};
    anchor.label = "fixture.synthetic.to.image";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;
    anchor.validator = &replace_synthetic_with_image_then_accept;

    const an::ResolvedAnchor result = an::resolve(anchor, replacement.range());

    ASSERT_TRUE(replacement.happened()) << "the synthetic mapping was not replaced by the fixture image";
    MEMORY_BASIC_INFORMATION memory_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(preferred_base), &memory_info, sizeof(memory_info)),
        sizeof(memory_info)
    );
    EXPECT_EQ(memory_info.Type, static_cast<DWORD>(MEM_IMAGE));
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReservedPrefixCodeOperandReplacementByImageFailsClosed)
{
    std::uintptr_t preferred_base = 0;
    {
        dmk_test::GenerationFixtureModule probe(dmk_test::RTTI_FIXTURE_VARIANT_A);
        ASSERT_TRUE(probe.ok()) << "variant A did not map while discovering its fixed base";
        preferred_base = probe.base();
        probe.release();
    }
    ASSERT_NE(preferred_base, 0U);

    ScopedSyntheticToImageReplacement replacement(preferred_base, true);
    ASSERT_TRUE(replacement.ok()) << "a reserved-prefix synthetic scope could not claim the fixture's fixed base";
    MEMORY_BASIC_INFORMATION prefix_info{};
    MEMORY_BASIC_INFORMATION code_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(preferred_base), &prefix_info, sizeof(prefix_info)),
        sizeof(prefix_info)
    );
    ASSERT_EQ(
        ::VirtualQuery(
            reinterpret_cast<const void *>(preferred_base + ScratchPage::PAGE_SIZE),
            &code_info,
            sizeof(code_info)
        ),
        sizeof(code_info)
    );
    ASSERT_EQ(prefix_info.State, static_cast<DWORD>(MEM_RESERVE));
    ASSERT_EQ(code_info.State, static_cast<DWORD>(MEM_COMMIT));
    ASSERT_EQ(code_info.Type, static_cast<DWORD>(MEM_PRIVATE));
    ASSERT_EQ(prefix_info.AllocationBase, code_info.AllocationBase);

    constexpr std::size_t code_offset = ScratchPage::PAGE_SIZE + TRANSACTION_MARKER_OFFSET;
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    replacement.put(code_offset, instruction);
    const sc::Candidate candidates[] = {sc::Candidate::direct("reserved-prefix-code", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.reserved.prefix";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor stable = an::resolve(anchor, replacement.range());
    ASSERT_EQ(stable.status, an::AnchorStatus::Resolved)
        << "a reserved scope with later committed evidence must remain a valid single allocation";
    ASSERT_EQ(stable.value, 0xF0);
    ASSERT_FALSE(stable.witness.image.present());

    anchor.validator = &replace_synthetic_with_image_then_accept;

    const an::ResolvedAnchor result = an::resolve(anchor, replacement.range());

    ASSERT_TRUE(replacement.happened()) << "the reserved-prefix allocation was not replaced by the fixture image";
    MEMORY_BASIC_INFORMATION image_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(preferred_base), &image_info, sizeof(image_info)),
        sizeof(image_info)
    );
    EXPECT_EQ(image_info.Type, static_cast<DWORD>(MEM_IMAGE));
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, SingleAllocationWithMoreThanSixtyFourRegionsResolves)
{
    ManyRegionScope scope;
    ASSERT_TRUE(scope.ok()) << "the alternating-protection allocation could not be created";
    const std::size_t instruction_offset = scope.page_size() * 64 + TRANSACTION_MARKER_OFFSET;
    constexpr std::array<std::uint8_t, 6> instruction{0x48, 0x05, 0xF0, 0x00, 0x00, 0x00};
    scope.put(instruction_offset, instruction);

    const sc::Candidate candidates[] = {sc::Candidate::direct("many-region-code", aob("48 05 F0 00 00 00"))};
    an::Anchor anchor{};
    anchor.label = "fixture.many.regions";
    anchor.kind = an::AnchorKind::CodeOperand;
    anchor.site = candidates;
    anchor.operand_kind = sc::OperandKind::Immediate;
    anchor.operand_index = 1;

    const an::ResolvedAnchor result = an::resolve(anchor, scope.range());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, 0xF0);
    EXPECT_EQ(result.domain, an::ResultDomain::Scalar);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ScopeSplitIntoMultipleAllocationsInsideValidatorFailsClosed)
{
    ScopedAllocationSplit split;
    ASSERT_TRUE(split.ok()) << "the two-granularity synthetic scope could not be reserved";
    const auto marker = transaction_marker(split.address() ^ ::GetCurrentProcessId());
    split.put(TRANSACTION_MARKER_OFFSET, marker);
    const sc::Candidate candidates[] = {sc::Candidate::direct("split-scope", aob(aob_for_bytes(marker)))};
    an::Anchor anchor{};
    anchor.label = "fixture.scope.split";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;
    anchor.validator = &split_scope_allocation_then_accept;

    const an::ResolvedAnchor result = an::resolve(anchor, split.range());

    ASSERT_TRUE(split.happened()) << "the one-allocation scope was not split during validation";
    MEMORY_BASIC_INFORMATION first_info{};
    MEMORY_BASIC_INFORMATION second_info{};
    ASSERT_EQ(
        ::VirtualQuery(reinterpret_cast<const void *>(split.address()), &first_info, sizeof(first_info)),
        sizeof(first_info)
    );
    ASSERT_EQ(
        ::VirtualQuery(
            reinterpret_cast<const void *>(split.address(s_split_granularity)),
            &second_info,
            sizeof(second_info)
        ),
        sizeof(second_info)
    );
    EXPECT_NE(first_info.AllocationBase, second_info.AllocationBase);
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ScopeSplitBetweenQuorumMembersFailsClosed)
{
    ScopedAllocationSplit split;
    ASSERT_TRUE(split.ok()) << "the two-granularity synthetic scope could not be reserved";
    const auto marker = transaction_marker(split.address() ^ ::GetCurrentProcessId());
    split.put(TRANSACTION_MARKER_OFFSET, marker);
    const std::uintptr_t value = split.address(TRANSACTION_MARKER_OFFSET);
    const sc::Candidate candidates[] = {sc::Candidate::direct("split-member", aob(aob_for_bytes(marker)))};

    an::Anchor scanned{};
    scanned.label = "fixture.scope.member";
    scanned.kind = an::AnchorKind::RipGlobal;
    scanned.site = candidates;
    scanned.pages = sc::Pages::Executable;

    an::Anchor replacement{};
    replacement.label = "fixture.scope.split";
    replacement.kind = an::AnchorKind::Manual;
    replacement.manual_value = static_cast<std::int64_t>(value);
    replacement.validate_manual = true;
    replacement.validator = &split_scope_allocation_then_accept;

    const an::Anchor *members[] = {&scanned, &replacement};
    an::Anchor quorum{};
    quorum.label = "fixture.scope.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    const an::ResolvedAnchor result = an::resolve(quorum, split.range());

    ASSERT_TRUE(split.happened()) << "the common scope was not split between the quorum member and publication";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementBetweenQuorumMembersFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    // The literal equals the export address, so only the generation mismatch prevents a successful quorum.
    const an::ResolvedAnchor probed = an::resolve(fixture_export_anchor(), dmk::Region::host());
    ASSERT_EQ(probed.status, an::AnchorStatus::Resolved);

    const an::Anchor export_member = fixture_export_anchor();
    // The replacement runs while the SECOND member resolves, so the first member's evidence is already a generation
    // behind by the time the quorum commits. A Manual member reads no image, so it cannot refuse on its own.
    an::Anchor pinned{};
    pinned.label = "fixture.pinned";
    pinned.kind = an::AnchorKind::Manual;
    pinned.manual_value = probed.value;
    pinned.validate_manual = true;
    pinned.validator = &swap_then_accept;

    const an::Anchor *members[] = {&export_member, &pinned};
    an::Anchor quorum{};
    quorum.label = "fixture.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementBetweenVtableMembersFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const std::uintptr_t target = swap.module().vtable();
    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);

    an::Anchor vtable_a{};
    vtable_a.label = "fixture.vtable.a";
    vtable_a.kind = an::AnchorKind::VtableIdentity;
    vtable_a.mangled = dmk_test::RTTI_FIXTURE_TYPE_A;

    an::Anchor replacement{};
    replacement.label = "fixture.swap";
    replacement.kind = an::AnchorKind::Manual;
    replacement.manual_value = static_cast<std::int64_t>(target);
    replacement.validate_manual = true;
    replacement.validator = &swap_then_accept;

    an::Anchor vtable_b{};
    vtable_b.label = "fixture.vtable.b";
    vtable_b.kind = an::AnchorKind::VtableIdentity;
    vtable_b.mangled = dmk_test::RTTI_FIXTURE_TYPE_B;

    const an::Anchor *members[] = {&vtable_a, &replacement, &vtable_b};
    an::Anchor quorum{};
    quorum.label = "fixture.vtable.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, scope);
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, ReplacementInsideTheQuorumValidatorFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    const an::ResolvedAnchor probed = an::resolve(fixture_export_anchor(), dmk::Region::host());
    ASSERT_EQ(probed.status, an::AnchorStatus::Resolved);

    const an::Anchor export_member = fixture_export_anchor();
    an::Anchor pinned{};
    pinned.label = "fixture.pinned";
    pinned.kind = an::AnchorKind::Manual;
    pinned.manual_value = probed.value;

    const an::Anchor *members[] = {&export_member, &pinned};
    an::Anchor quorum{};
    quorum.label = "fixture.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    // The quorum validator runs after the vote inside commit. This isolates the last replacement window before witness
    // publication.
    quorum.validator = &swap_then_accept;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, StableQuorumWitnessCarriesTheCapturedOwnerIdentity)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";

    const an::ResolvedAnchor probed = an::resolve(fixture_export_anchor(), dmk::Region::host());
    ASSERT_EQ(probed.status, an::AnchorStatus::Resolved);

    const an::Anchor export_member = fixture_export_anchor();
    an::Anchor pinned{};
    pinned.label = "fixture.pinned";
    pinned.kind = an::AnchorKind::Manual;
    pinned.manual_value = probed.value;

    const an::Anchor *members[] = {&export_member, &pinned};
    an::Anchor quorum{};
    quorum.label = "fixture.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    quorum.validator = &accept_any;

    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::host());
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, probed.value);
    ASSERT_TRUE(result.witness.image.present());
    // The witness copies the address owner's captured identity, which an undisturbed same-module export resolve leaves
    // equal to the module's current identity.
    EXPECT_EQ(result.witness.image, sc::image_identity(dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A)));
    EXPECT_EQ(probed.witness.image, result.witness.image) << "the flat and corroborated paths must agree";
}

TEST(AnchorTrustTransactionTest, StableCrossModuleImageOwnersCanCorroborate)
{
    dmk_test::GenerationFixtureModule target_module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(target_module.ok()) << "variant A did not map";
    ASSERT_NE(target_module.prepare(), 0U) << "variant A could not lay down its RTTI graph";
    ExportFixture evidence_module;
    ASSERT_TRUE(evidence_module.ok()) << "the independent evidence module did not map";

    const dmk::Region evidence_scope = dmk::Region::module_named(ExportFixture::MODULE_NAME);
    const sc::ImageIdentity target_identity =
        sc::image_identity(dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A));
    const sc::ImageIdentity evidence_identity = sc::image_identity(evidence_scope);
    ASSERT_TRUE(target_identity.present());
    ASSERT_TRUE(evidence_identity.present());
    ASSERT_NE(target_identity, evidence_identity);

    const an::Anchor export_member = fixture_export_anchor();
    const an::ResolvedAnchor export_result = an::resolve(export_member, evidence_scope);
    ASSERT_EQ(export_result.status, an::AnchorStatus::Resolved);
    const std::uintptr_t target = static_cast<std::uintptr_t>(export_result.value);

    const std::uintptr_t instruction_address = evidence_module.proc("dmk_scan_marker");
    ASSERT_NE(instruction_address, 0U);
    std::array<std::uint8_t, 16> original_bytes{};
    std::memcpy(original_bytes.data(), reinterpret_cast<const void *>(instruction_address), original_bytes.size());
    std::array<std::uint8_t, 10> instruction{0x48, 0xB8};
    std::memcpy(instruction.data() + 2, &target, sizeof(target));
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(instruction_address),
            original_bytes.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(instruction_address), instruction.data(), instruction.size());

    const sc::Candidate candidates[] = {sc::Candidate::direct("cross-module-operand", aob(aob_for_bytes(instruction)))};
    an::Anchor operand_member{};
    operand_member.label = "fixture.cross.module.operand";
    operand_member.kind = an::AnchorKind::CodeOperand;
    operand_member.site = candidates;
    operand_member.operand_kind = sc::OperandKind::Immediate;
    operand_member.operand_index = 1;

    const an::ResolvedAnchor operand_result = an::resolve(operand_member, evidence_scope);
    const an::Anchor *members[] = {&export_member, &operand_member};
    an::Anchor quorum{};
    quorum.label = "fixture.cross.module.quorum";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;
    const an::ResolvedAnchor result = an::resolve(quorum, evidence_scope);

    std::memcpy(reinterpret_cast<void *>(instruction_address), original_bytes.data(), original_bytes.size());
    DWORD ignored = 0;
    ASSERT_TRUE(
        ::VirtualProtect(reinterpret_cast<void *>(instruction_address), original_bytes.size(), old_protection, &ignored)
    );

    ASSERT_EQ(operand_result.status, an::AnchorStatus::Resolved);
    ASSERT_EQ(static_cast<std::uintptr_t>(operand_result.value), target);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(static_cast<std::uintptr_t>(result.value), target);
    EXPECT_EQ(result.domain, an::ResultDomain::CodeSite);
    EXPECT_EQ(result.witness.image, target_identity);
}

TEST(AnchorTrustTransactionTest, WideExecutableScopeAcrossAllocationsFailsClosed)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    const std::uintptr_t target = module.prepare();
    ASSERT_NE(target, 0U) << "variant A could not lay down its RTTI graph";
    ASSERT_GT(module.base(), TRANSACTION_PAGE_GAP);

    FixedExecutablePage page(module.base() - TRANSACTION_PAGE_GAP);
    ASSERT_TRUE(page.ok()) << "the fixed transaction page could not be reserved";
    const auto marker = transaction_marker(target ^ page.address() ^ ::GetCurrentProcessId());
    page.put(TRANSACTION_MARKER_OFFSET, marker);
    const std::uintptr_t marker_address = page.address(TRANSACTION_MARKER_OFFSET);
    const sc::Candidate candidates[] = {
        sc::Candidate::direct("wide-scope-target", aob(aob_for_bytes(marker)), target_delta(marker_address, target))
    };

    an::Anchor anchor{};
    anchor.label = "fixture.wide.target";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;

    const an::ResolvedAnchor result = an::resolve(anchor, transaction_scope(page, target));
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST(AnchorTrustTransactionTest, ReplacementDuringDiscoveryAfterScopeOwnerCaptureFailsClosed)
{
    std::array<std::uint8_t, TRANSACTION_MARKER_BYTES> shared_header{};
    std::uintptr_t fixture_base = 0;
    {
        dmk_test::GenerationFixtureModule variant_a(dmk_test::RTTI_FIXTURE_VARIANT_A);
        ASSERT_TRUE(variant_a.ok()) << "variant A did not map while sampling its shared header";
        fixture_base = variant_a.base();
        std::memcpy(shared_header.data(), reinterpret_cast<const void *>(fixture_base), shared_header.size());
    }
    {
        dmk_test::GenerationFixtureModule variant_b(dmk_test::RTTI_FIXTURE_VARIANT_B);
        ASSERT_TRUE(variant_b.ok()) << "variant B did not map while checking its shared header";
        ASSERT_EQ(variant_b.base(), fixture_base);
        ASSERT_EQ(
            std::memcmp(shared_header.data(), reinterpret_cast<const void *>(fixture_base), shared_header.size()),
            0
        ) << "the discovery replacement needs byte-identical evidence in both images";
    }

    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    ASSERT_EQ(swap.base(), fixture_base);
    const sc::Candidate candidates[] = {sc::Candidate::direct("shared-header", aob(aob_for_bytes(shared_header)))};
    an::Anchor anchor{};
    anchor.label = "fixture.discovery.owner";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Readable;
    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    an::ResolvedAnchor result{};
    {
        ScopedDiscoverySweepHook hook;
        result = an::resolve(anchor, scope);
    }
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not replace A after the discovery sweep";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_EQ(result.domain, an::ResultDomain::Unknown);
    EXPECT_FALSE(result.witness.image.present());
}

#endif

TEST(AnchorTrustTransactionTest, TemporalDriftOverridesPhysicalDependenceStatus)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";
    const std::uintptr_t target = swap.module().vtable();
    const std::uintptr_t marker_address = swap.module().table();
    const auto marker = transaction_marker(target ^ marker_address ^ ::GetCurrentProcessId());
    DWORD old_protection = 0;
    ASSERT_TRUE(
        ::VirtualProtect(
            reinterpret_cast<void *>(marker_address),
            marker.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )
    );
    std::memcpy(reinterpret_cast<void *>(marker_address), marker.data(), marker.size());

    const sc::Candidate full_candidates[] = {
        sc::Candidate::direct("module-full", aob(aob_for_bytes(marker)), target_delta(marker_address, target))
    };
    constexpr std::size_t suffix_offset = 8;
    const std::span<const std::uint8_t> suffix{marker.data() + suffix_offset, marker.size() - suffix_offset};
    const sc::Candidate suffix_candidates[] = {sc::Candidate::direct(
        "module-suffix",
        aob(aob_for_bytes(suffix)),
        target_delta(marker_address + suffix_offset, target)
    )};

    an::Anchor full{};
    full.label = "fixture.module.full";
    full.kind = an::AnchorKind::RipGlobal;
    full.site = full_candidates;
    full.pages = sc::Pages::Executable;

    an::Anchor suffix_anchor{};
    suffix_anchor.label = "fixture.module.suffix";
    suffix_anchor.kind = an::AnchorKind::RipGlobal;
    suffix_anchor.site = suffix_candidates;
    suffix_anchor.pages = sc::Pages::Executable;

    an::Anchor replacement{};
    replacement.label = "fixture.swap";
    replacement.kind = an::AnchorKind::Manual;
    replacement.manual_value = static_cast<std::int64_t>(target);
    replacement.validate_manual = true;
    replacement.validator = &swap_then_accept;

    const an::Anchor *members[] = {&full, &suffix_anchor, &replacement};
    an::Anchor quorum{};
    quorum.label = "fixture.physical.drift";
    quorum.kind = an::AnchorKind::Quorum;
    quorum.quorum_members = members;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(quorum, dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A));
    s_anchor_swap = nullptr;

    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed)
        << "temporal drift must override the otherwise valid QuorumNotIndependent diagnosis";
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}

TEST(AnchorTrustTransactionTest, IdentitylessAddressScopeResolvesWithoutAnImage)
{
    // A synthetic scope belongs to no mapped image, so there is no identity to capture and none to invalidate. Those
    // resolves must stay exactly as they were rather than failing closed for want of a key.
    ScratchPage page;
    ASSERT_TRUE(page.ok());
    page.put(0x100, {0xD1, 0x4A, 0x77, 0x0B, 0xC3, 0x95, 0xE2, 0x68});

    const sc::Candidate candidates[] = {sc::Candidate::direct("synthetic-address", aob("D1 4A 77 0B C3 95 E2 68"))};
    an::Anchor anchor{};
    anchor.label = "synthetic.address";
    anchor.kind = an::AnchorKind::RipGlobal;
    anchor.site = candidates;
    anchor.pages = sc::Pages::Executable;

    const an::ResolvedAnchor result = an::resolve(anchor, page.range());
    EXPECT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(page.addr(0x100)));
    EXPECT_FALSE(result.witness.image.present());
}

// The scope-evidence path captures the scanned image key. Export-module cases do not reach that branch.
TEST(AnchorTrustTransactionTest, StableScopeEvidenceCarriesTheScopeImageIdentity)
{
    dmk_test::GenerationFixtureModule module(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_TRUE(module.ok()) << "variant A did not map";
    ASSERT_NE(module.prepare(), 0U) << "variant A could not lay down its RTTI graph";

    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(scope.base.raw(), 0U);

    an::Anchor anchor{};
    anchor.label = "fixture.vtable";
    anchor.kind = an::AnchorKind::VtableIdentity;
    anchor.mangled = dmk_test::RTTI_FIXTURE_TYPE_A;

    const an::ResolvedAnchor result = an::resolve(anchor, scope);
    ASSERT_EQ(result.status, an::AnchorStatus::Resolved);
    EXPECT_EQ(result.value, static_cast<std::int64_t>(module.vtable()));
    ASSERT_TRUE(result.witness.image.present());
    EXPECT_EQ(result.witness.image, sc::image_identity(scope));
}

TEST(AnchorTrustTransactionTest, ScopeEvidenceModuleReplacementFailsClosed)
{
    dmk_test::SameBaseSwap swap;
    ASSERT_TRUE(swap.load_a()) << "variant A did not map or could not lay down its RTTI graph";

    const dmk::Region scope = dmk::Region::module_named(dmk_test::RTTI_FIXTURE_VARIANT_A);
    ASSERT_NE(scope.base.raw(), 0U);

    an::Anchor anchor{};
    anchor.label = "fixture.vtable";
    anchor.kind = an::AnchorKind::VtableIdentity;
    anchor.mangled = dmk_test::RTTI_FIXTURE_TYPE_A;
    anchor.validator = &swap_then_accept;

    s_anchor_swap = &swap;
    s_anchor_swap_happened = false;
    const an::ResolvedAnchor result = an::resolve(anchor, scope);
    s_anchor_swap = nullptr;

    // Validator entry proves that the scan found a vtable and reached commit.
    ASSERT_TRUE(s_anchor_swap_happened) << "variant B did not map at variant A's base; the replacement never happened";
    EXPECT_EQ(result.status, an::AnchorStatus::Failed);
    EXPECT_EQ(result.value, 0);
    EXPECT_FALSE(result.witness.image.present());
}
