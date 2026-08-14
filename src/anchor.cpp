/**
 * @file anchor.cpp
 * @brief The declarative anchor registry dispatches each anchor kind to its v4 backend and reports drift uniformly.
 * @details Five kinds use one self-heal backend and fail closed. Manual has no backend, and CallArgHome has no
 *          resolver. Unset fails closed, while Quorum combines independent member results. This layer maps each typed
 *          backend error to AnchorStatus. It also applies the optional validator and per-game ScanProfile defaults.
 *          The drift fingerprints live in anchor_evidence.cpp and the quality gate in anchor_gate.cpp.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"
#include "internal/anchor_evidence.hpp"
#include "internal/anchor_resolution.hpp"
#include "internal/export_resolution.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace DetourModKit
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    namespace detail
    {
        void (*g_anchor_after_named_export_lookup_test_hook)() noexcept = nullptr;
        void (*g_anchor_after_owner_identity_test_hook)() noexcept = nullptr;
        void (*g_anchor_after_confirmed_owner_identity_test_hook)() noexcept = nullptr;
        void (*g_anchor_after_witness_test_hook)() noexcept = nullptr;
    } // namespace detail
#endif

    namespace anchor
    {
        namespace
        {
            // Applies the profile's candidate order through a local span because read_code_constant has no order
            // parameter. The local copy preserves the caller's static table.
            [[nodiscard]] std::span<const scan::Candidate> profiled_candidates(const ScanProfile &profile,
                                                                               std::span<const scan::Candidate> site,
                                                                               std::vector<scan::Candidate> &ordered)
            {
                if (profile.candidate_order == scan::CandidateOrder::AsDeclared || site.size() < 2)
                {
                    return site;
                }

                std::vector<std::size_t> indices(site.size());
                const std::size_t count = scan::order_candidates(profile.candidate_order, site, indices);
                ordered.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                {
                    ordered.push_back(site[indices[i]]);
                }
                return ordered;
            }

            // This agreement test fails closed. Unsigned subtraction converts a negative tolerance to a huge bound
            // that accepts almost any gap, so reject it first.
            [[nodiscard]] bool quorum_values_agree(std::int64_t first, std::int64_t second, QuorumMatch match,
                                                   std::int64_t tolerance) noexcept
            {
                if (match == QuorumMatch::ExactValue)
                {
                    return first == second;
                }
                if (tolerance < 0)
                {
                    return false;
                }
                // Pair order makes the gap hi - lo. Unsigned subtraction avoids signed overflow across a large address
                // span.
                const std::int64_t lo = (first < second) ? first : second;
                const std::int64_t hi = (first < second) ? second : first;
                const auto gap = static_cast<std::uint64_t>(hi) - static_cast<std::uint64_t>(lo);
                return gap <= static_cast<std::uint64_t>(tolerance);
            }

            // These per-kind enum range checks fail closed. A hand-built out-of-range enum reports AnchorStatus::Failed
            // at this boundary and cannot silently select a resolution mode.
            [[nodiscard]] constexpr bool valid_operand_kind(scan::OperandKind kind) noexcept
            {
                return kind == scan::OperandKind::Immediate || kind == scan::OperandKind::MemoryDisplacement;
            }

            [[nodiscard]] constexpr bool valid_string_encoding(scan::StringEncoding encoding) noexcept
            {
                return encoding == scan::StringEncoding::Utf8 || encoding == scan::StringEncoding::Utf16le;
            }

            [[nodiscard]] constexpr bool valid_xref_return(scan::XrefReturn mode) noexcept
            {
                switch (mode)
                {
                case scan::XrefReturn::ReferencingInstruction:
                case scan::XrefReturn::EnclosingFunction:
                case scan::XrefReturn::StringPointerSlot:
                    return true;
                }
                return false;
            }

            [[nodiscard]] constexpr bool valid_quorum_match(QuorumMatch match) noexcept
            {
                return match == QuorumMatch::ExactValue || match == QuorumMatch::WithinTolerance;
            }

            // CodeOperand consumes the order locally. RipGlobal delegates validation to scan::resolve.
            [[nodiscard]] constexpr bool valid_candidate_order(scan::CandidateOrder order) noexcept
            {
                return order == scan::CandidateOrder::AsDeclared || order == scan::CandidateOrder::UniqueFirst;
            }

            /**
             * @brief The physical source one resolved member's value depends on.
             * @details Two members that resolve from one physical source share one failure domain. A quorum must count
             *          them once. Two spans suffice for every current backend. If a backend adds a third span, raise
             *          this bound. add() discards excess spans, which lose dependency evidence.
             */
            class PhysicalProvenance
            {
            public:
                void add(Region span) noexcept
                {
                    if (!span.base || span.size == 0)
                    {
                        return;
                    }
                    if (m_size < m_spans.size())
                    {
                        m_spans[m_size++] = span;
                    }
                }

                void add(const DetourModKit::detail::ExportResolution &resolution) noexcept
                {
                    if (resolution.present())
                    {
                        m_export = resolution;
                    }
                }

                [[nodiscard]] bool intersects(const PhysicalProvenance &other) const noexcept
                {
                    if (DetourModKit::detail::same_export_site(m_export, other.m_export))
                    {
                        return true;
                    }
                    for (std::size_t i = 0; i < m_size; ++i)
                    {
                        for (std::size_t j = 0; j < other.m_size; ++j)
                        {
                            if (overlaps(m_spans[i], other.m_spans[j]))
                            {
                                return true;
                            }
                        }
                    }
                    return false;
                }

            private:
                [[nodiscard]] static bool overlaps(Region a, Region b) noexcept
                {
                    return a.base.raw() < b.end().raw() && b.base.raw() < a.end().raw();
                }

                std::array<Region, 2> m_spans{};
                std::size_t m_size = 0;
                DetourModKit::detail::ExportResolution m_export{};
            };

            // Counts votes that agree with a candidate cluster center. A negative WithinTolerance rejects even the
            // center against itself, so the quorum fails closed.
            [[nodiscard]] std::size_t votes_agreeing_with(std::int64_t center, std::span<const std::int64_t> votes,
                                                          QuorumMatch match, std::int64_t tolerance) noexcept
            {
                std::size_t agree = 0;
                for (const std::int64_t vote : votes)
                {
                    if (quorum_values_agree(center, vote, match, tolerance))
                    {
                        ++agree;
                    }
                }
                return agree;
            }

            // Maps a flat anchor backend to its physical source. RipGlobal uses its selected ladder mode.
            [[nodiscard]] PhysicalSource physical_source_of(AnchorKind kind) noexcept
            {
                switch (kind)
                {
                case AnchorKind::RipGlobal:
                    return PhysicalSource::None;
                case AnchorKind::StringXref:
                    return PhysicalSource::StringLiteral;
                case AnchorKind::VtableIdentity:
                    return PhysicalSource::TypeIdentity;
                case AnchorKind::ExportName:
                    return PhysicalSource::ExportTable;
                case AnchorKind::CodeOperand:
                    return PhysicalSource::CodeOperand;
                case AnchorKind::Manual:
                    return PhysicalSource::ManualPin;
                case AnchorKind::Quorum:
                    return PhysicalSource::Corroborated;
                case AnchorKind::CallArgHome:
                case AnchorKind::Unset:
                    return PhysicalSource::None;
                }
                return PhysicalSource::None;
            }

            [[nodiscard]] PhysicalSource physical_source_of(scan::Mode mode) noexcept
            {
                switch (mode)
                {
                case scan::Mode::Direct:
                case scan::Mode::RipRelative:
                    return PhysicalSource::ByteSignature;
                case scan::Mode::RttiVtable:
                    return PhysicalSource::TypeIdentity;
                case scan::Mode::StringXref:
                    return PhysicalSource::StringLiteral;
                }
                return PhysicalSource::None;
            }

            // Commits a backend-resolved value through the optional fail-closed validator. A validator miss reports
            // Failed with no value, identical to a backend miss.
            void commit_resolved(const Anchor &anchor, ResolvedAnchor &result, std::int64_t value) noexcept
            {
                // Backend-resolved targets use an opt-in required-validator policy. Manual and Quorum are exempt. A
                // pinned literal is not a resolved target, and Quorum corroboration already supplies verification.
                if (anchor.require_validator && anchor.kind != AnchorKind::Quorum &&
                    anchor.kind != AnchorKind::Manual && anchor.validator == nullptr)
                {
                    result.status = AnchorStatus::Failed;
                    result.value = 0;
                    return;
                }
                if (anchor.validator != nullptr && !anchor.validator(value, anchor.validator_context))
                {
                    result.status = AnchorStatus::Failed;
                    result.value = 0;
                    return;
                }
                result.value = value;
                result.status = AnchorStatus::Resolved;
            }

            [[nodiscard]] ResolvedAnchor failed_anchor_result(const Anchor &anchor) noexcept
            {
                return ResolvedAnchor{anchor.label, anchor.kind, AnchorStatus::Failed, 0};
            }

            enum class OwnerBacking : std::uint8_t
            {
                None,
                Missing,
                Image,
                Private,
                Mapped
            };

            /**
             * @struct OwnerKey
             * @brief The memory source an anchor read and, for an image, that image's PE identity.
             * @details Synthetic ranges carry their OS region class and allocation base but no PE identity. This key
             *          remains valid while the range stays stable. It detects a synthetic-to-image transition before
             *          publication.
             */
            struct OwnerKey
            {
                std::uintptr_t address{0};
                std::uintptr_t allocation_base{0};
                scan::ImageIdentity identity{};
                OwnerBacking backing{OwnerBacking::None};

                [[nodiscard]] constexpr bool tracked() const noexcept { return backing != OwnerBacking::None; }
                [[nodiscard]] constexpr bool has_module() const noexcept { return backing == OwnerBacking::Image; }
                [[nodiscard]] constexpr bool operator==(const OwnerKey &other) const noexcept = default;
            };

            constexpr std::size_t MAX_EVIDENCE_OWNER_KEYS = 3;

            /**
             * @brief Returns whether the complete scan scope stays inside one reserved allocation.
             * @details A single allocation lets one captured owner key cover the complete evidence domain. A wider
             *          sweep leaves unrelated memory sources outside that key.
             */
            [[nodiscard]] bool scope_is_single_allocation(Region scope) noexcept
            {
                if (scope.base.raw() == 0 || scope.size == 0 || scope.base.raw() > UINTPTR_MAX - scope.size)
                {
                    return false;
                }
                MEMORY_BASIC_INFORMATION memory_info{};
                if (::VirtualQuery(scope.base.as<const void *>(), &memory_info, sizeof(memory_info)) == 0 ||
                    memory_info.AllocationBase == nullptr)
                {
                    return false;
                }
                const void *const allocation_base = memory_info.AllocationBase;
                const std::uintptr_t scope_end = scope.base.raw() + scope.size;
                std::uintptr_t cursor = scope.base.raw();
                while (cursor < scope_end)
                {
                    if (::VirtualQuery(reinterpret_cast<const void *>(cursor), &memory_info, sizeof(memory_info)) ==
                            0 ||
                        memory_info.AllocationBase != allocation_base)
                    {
                        return false;
                    }
                    const std::uintptr_t region_base = reinterpret_cast<std::uintptr_t>(memory_info.BaseAddress);
                    if (memory_info.RegionSize == 0 || region_base > UINTPTR_MAX - memory_info.RegionSize)
                    {
                        return false;
                    }
                    const std::uintptr_t region_end = region_base + memory_info.RegionSize;
                    if (region_end <= cursor)
                    {
                        return false;
                    }
                    if (region_end >= scope_end)
                    {
                        return true;
                    }
                    cursor = region_end;
                }
                return false;
            }

            struct ResolutionOwnerKeys
            {
                std::array<OwnerKey, MAX_EVIDENCE_OWNER_KEYS> evidence{};
                std::size_t evidence_count{0};
                OwnerKey value{};
                bool overflowed{false};
                bool requires_single_allocation{false};

                void add_evidence(const OwnerKey &key) noexcept
                {
                    if (!key.tracked())
                    {
                        return;
                    }
                    for (std::size_t i = 0; i < evidence_count; ++i)
                    {
                        if (evidence[i] == key)
                        {
                            return;
                        }
                    }
                    if (evidence_count == evidence.size())
                    {
                        overflowed = true;
                        return;
                    }
                    evidence[evidence_count++] = key;
                }
            };

            /**
             * @brief Captures owner identity for an evidence or value address.
             * @details A committed non-image range carries a synthetic owner key without a PE identity. A lost
             *          address carries a fail-closed key. A MEM_IMAGE range with an unreadable PE identity does too.
             */
            [[nodiscard]] OwnerKey capture_owner_key(Region region) noexcept
            {
                if (region.base.raw() == 0 || region.size == 0 ||
                    !DetourModKit::detail::is_plausible_ptr(region.base.raw()))
                {
                    return OwnerKey{};
                }
                MEMORY_BASIC_INFORMATION memory_info{};
                if (::VirtualQuery(region.base.as<const void *>(), &memory_info, sizeof(memory_info)) == 0 ||
                    memory_info.State != MEM_COMMIT)
                {
                    return OwnerKey{region.base.raw(), 0, {}, OwnerBacking::Missing};
                }
                const std::uintptr_t allocation_base = reinterpret_cast<std::uintptr_t>(memory_info.AllocationBase);
                if (allocation_base == 0)
                {
                    return OwnerKey{region.base.raw(), 0, {}, OwnerBacking::Missing};
                }
                if (memory_info.Type == MEM_IMAGE)
                {
                    return OwnerKey{allocation_base, allocation_base,
                                    scan::image_identity(Region{Address{allocation_base}, 1}), OwnerBacking::Image};
                }
                if (memory_info.Type == MEM_PRIVATE)
                {
                    return OwnerKey{region.base.raw(), allocation_base, {}, OwnerBacking::Private};
                }
                if (memory_info.Type == MEM_MAPPED)
                {
                    return OwnerKey{region.base.raw(), allocation_base, {}, OwnerBacking::Mapped};
                }
                return OwnerKey{region.base.raw(), allocation_base, {}, OwnerBacking::Missing};
            }

            /**
             * @brief Captures the first committed region inside a scope whose allocation was already validated.
             * @details A reserved prefix has no region class. The first committed page's key places scalar and
             *          address-domain backends in the same region-class transaction.
             */
            [[nodiscard]] OwnerKey capture_scope_owner_key(Region scope) noexcept
            {
                if (scope.base.raw() == 0 || scope.size == 0 || scope.base.raw() > UINTPTR_MAX - scope.size)
                {
                    return capture_owner_key(scope);
                }
                const std::uintptr_t scope_end = scope.base.raw() + scope.size;
                std::uintptr_t cursor = scope.base.raw();
                while (cursor < scope_end)
                {
                    MEMORY_BASIC_INFORMATION memory_info{};
                    if (::VirtualQuery(reinterpret_cast<const void *>(cursor), &memory_info, sizeof(memory_info)) == 0)
                    {
                        break;
                    }
                    const std::uintptr_t region_base = reinterpret_cast<std::uintptr_t>(memory_info.BaseAddress);
                    if (memory_info.RegionSize == 0 || region_base > UINTPTR_MAX - memory_info.RegionSize)
                    {
                        break;
                    }
                    if (memory_info.State == MEM_COMMIT)
                    {
                        const std::uintptr_t committed_address = (cursor > region_base) ? cursor : region_base;
                        return capture_owner_key(Region{Address{committed_address}, 1});
                    }
                    const std::uintptr_t region_end = region_base + memory_info.RegionSize;
                    if (region_end <= cursor || region_end >= scope_end)
                    {
                        break;
                    }
                    cursor = region_end;
                }
                return capture_owner_key(scope);
            }

            /// Returns whether an explicit export module still resolves to its captured region and owner key.
            [[nodiscard]] bool named_export_owner_current(const Anchor &anchor, Region expected_region,
                                                          const OwnerKey &expected_owner) noexcept
            {
                if (anchor.kind != AnchorKind::ExportName || anchor.export_module.empty())
                {
                    return true;
                }
                const Region live_region = Region::module_named(anchor.export_module);
                return live_region.base == expected_region.base && live_region.size == expected_region.size &&
                       capture_owner_key(live_region) == expected_owner;
            }

            /**
             * @brief Returns true while the captured memory source remains current at its address.
             * @details Synthetic ranges retain region class and allocation base. Image checks surround two PE identity
             *          reads with MEM_IMAGE and allocation-base checks. A same-base image or private-header replacement
             *          therefore fails closed.
             */
            [[nodiscard]] bool owner_key_current(const OwnerKey &key) noexcept
            {
                if (!key.tracked())
                {
                    return true;
                }
                if (key.backing == OwnerBacking::Missing)
                {
                    return false;
                }
                MEMORY_BASIC_INFORMATION memory_info{};
                if (::VirtualQuery(reinterpret_cast<const void *>(key.address), &memory_info, sizeof(memory_info)) ==
                        0 ||
                    memory_info.State != MEM_COMMIT ||
                    reinterpret_cast<std::uintptr_t>(memory_info.AllocationBase) != key.allocation_base)
                {
                    return false;
                }
                if (!key.has_module())
                {
                    const DWORD expected_type = key.backing == OwnerBacking::Private ? MEM_PRIVATE : MEM_MAPPED;
                    return memory_info.Type == expected_type;
                }
                if (memory_info.Type != MEM_IMAGE || !key.identity.present())
                {
                    return false;
                }
                const scan::ImageIdentity live_identity = scan::image_identity(Region{Address{key.allocation_base}, 1});
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *const hook = DetourModKit::detail::g_anchor_after_owner_identity_test_hook)
                {
                    hook();
                }
#endif
                MEMORY_BASIC_INFORMATION confirmed_info{};
                if (::VirtualQuery(reinterpret_cast<const void *>(key.address), &confirmed_info,
                                   sizeof(confirmed_info)) == 0 ||
                    confirmed_info.State != MEM_COMMIT || confirmed_info.Type != MEM_IMAGE ||
                    reinterpret_cast<std::uintptr_t>(confirmed_info.AllocationBase) != key.allocation_base)
                {
                    return false;
                }
                const scan::ImageIdentity confirmed_identity =
                    scan::image_identity(Region{Address{key.allocation_base}, 1});
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (auto *const hook = DetourModKit::detail::g_anchor_after_confirmed_owner_identity_test_hook)
                {
                    hook();
                }
#endif
                MEMORY_BASIC_INFORMATION final_info{};
                if (::VirtualQuery(reinterpret_cast<const void *>(key.address), &final_info, sizeof(final_info)) == 0 ||
                    final_info.State != MEM_COMMIT || final_info.Type != MEM_IMAGE ||
                    reinterpret_cast<std::uintptr_t>(final_info.AllocationBase) != key.allocation_base)
                {
                    return false;
                }
                return live_identity == key.identity && confirmed_identity == key.identity;
            }

            /// Returns whether two captured keys can describe one coherent generation.
            [[nodiscard]] constexpr bool owner_keys_compatible(const OwnerKey &first, const OwnerKey &second) noexcept
            {
                return !first.has_module() || !second.has_module() || first.allocation_base != second.allocation_base ||
                       first.identity == second.identity;
            }

            /**
             * @brief Decides whether every image that supplied evidence remains the same image.
             * @details Run this check after the value commits because the validator can replace a module. A replacement
             *          between two member resolves mixes image generations. Restoration before this check does not
             *          repair that vote.
             */
            [[nodiscard]] bool evidence_images_coherent(const ResolutionOwnerKeys &local,
                                                        std::span<const OwnerKey> members) noexcept
            {
                if (local.overflowed)
                {
                    return false;
                }

                std::array<OwnerKey, MAX_EVIDENCE_OWNER_KEYS + 1> local_keys{};
                std::size_t local_count = local.evidence_count;
                std::copy_n(local.evidence.begin(), local_count, local_keys.begin());
                if (local.value.tracked())
                {
                    local_keys[local_count++] = local.value;
                }
                for (std::size_t i = 0; i < local_count; ++i)
                {
                    if (!owner_key_current(local_keys[i]))
                    {
                        return false;
                    }
                    for (std::size_t j = i + 1; j < local_count; ++j)
                    {
                        if (!owner_keys_compatible(local_keys[i], local_keys[j]))
                        {
                            return false;
                        }
                    }
                    for (const OwnerKey &member : members)
                    {
                        if (!owner_keys_compatible(local_keys[i], member))
                        {
                            return false;
                        }
                    }
                }
                for (std::size_t i = 0; i < members.size(); ++i)
                {
                    if (!owner_key_current(members[i]))
                    {
                        return false;
                    }
                    for (std::size_t j = i + 1; j < members.size(); ++j)
                    {
                        if (!owner_keys_compatible(members[i], members[j]))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }

            /// Returns whether @p domain carries an address rather than a scalar.
            [[nodiscard]] constexpr bool is_address_domain(ResultDomain domain) noexcept
            {
                return domain == ResultDomain::CodeSite || domain == ResultDomain::DataAddress ||
                       domain == ResultDomain::VtableAddress;
            }

            /**
             * @brief Captures an address-domain value's owner before its validator.
             * @details Synthetic addresses keep an owner key without an image identity. An unreadable loader-backed
             *          address keeps a fail-closed image key.
             */
            [[nodiscard]] OwnerKey capture_value_owner(const Anchor &anchor, std::int64_t value) noexcept
            {
                if (is_address_domain(declared_domain(anchor)))
                {
                    return capture_owner_key(Region{Address{static_cast<std::uintptr_t>(value)}, 1});
                }
                return OwnerKey{};
            }

            /// Appends @p key when it identifies a tracked memory source.
            void append_owner_key(std::vector<OwnerKey> &keys, const OwnerKey &key)
            {
                if (key.tracked())
                {
                    keys.push_back(key);
                }
            }

            /// Appends every tracked owner key from @p owner_keys.
            void append_owner_keys(std::vector<OwnerKey> &keys, const ResolutionOwnerKeys &owner_keys)
            {
                for (std::size_t i = 0; i < owner_keys.evidence_count; ++i)
                {
                    append_owner_key(keys, owner_keys.evidence[i]);
                }
                append_owner_key(keys, owner_keys.value);
            }

            /**
             * @brief Returns whether a backend reads evidence from the scan scope's own memory source.
             * @details ExportName captures its effective export module instead. Manual pins a literal.
             *          Quorum inherits its members' keys. The two kinds without resolvers read nothing.
             */
            [[nodiscard]] constexpr bool evidence_module_is_scope(AnchorKind kind) noexcept
            {
                switch (kind)
                {
                case AnchorKind::VtableIdentity:
                case AnchorKind::RipGlobal:
                case AnchorKind::CodeOperand:
                case AnchorKind::StringXref:
                    return true;
                case AnchorKind::ExportName:
                case AnchorKind::Manual:
                case AnchorKind::Quorum:
                case AnchorKind::CallArgHome:
                case AnchorKind::Unset:
                    return false;
                }
                return false;
            }

            static_assert(evidence_module_is_scope(AnchorKind::VtableIdentity));
            static_assert(evidence_module_is_scope(AnchorKind::RipGlobal));
            static_assert(evidence_module_is_scope(AnchorKind::CodeOperand));
            static_assert(evidence_module_is_scope(AnchorKind::StringXref));
            static_assert(!evidence_module_is_scope(AnchorKind::ExportName));
            static_assert(!evidence_module_is_scope(AnchorKind::Manual));
            static_assert(!evidence_module_is_scope(AnchorKind::Quorum));
            static_assert(!evidence_module_is_scope(AnchorKind::CallArgHome));
            static_assert(!evidence_module_is_scope(AnchorKind::Unset));

        } // anonymous namespace

        scan::StringRefQuery apply_profile(const ScanProfile &profile, scan::StringRefQuery query) noexcept
        {
            // This policy only widens the scan. A per-anchor broad_match value stays set. The profile can enable broad
            // mode but cannot disable it.
            query.broad_match = query.broad_match || profile.default_broad_string_xref;
            return query;
        }

        namespace
        {
            ResolvedAnchor resolve_with_profile_impl(const Anchor &anchor, const ScanProfile &profile, Region scope,
                                                     PhysicalProvenance *provenance,
                                                     ResolutionOwnerKeys *owner_keys_out, Region *winning_span_out)
            {
                if (provenance != nullptr)
                {
                    *provenance = PhysicalProvenance{};
                }
                if (owner_keys_out != nullptr)
                {
                    *owner_keys_out = ResolutionOwnerKeys{};
                }
                if (winning_span_out != nullptr)
                {
                    *winning_span_out = Region{};
                }
                ResolvedAnchor result{anchor.label, anchor.kind, AnchorStatus::Unresolved, 0};
                PhysicalSource resolved_source = physical_source_of(anchor.kind);
                // Only a byte-signature rung witnesses a literal span, so this stays absent for every other backend.
                scan::WinningEvidence resolved_evidence{};
                Region resolved_winning_span{};

                // A denied kind fails closed before any scan and is never silently replaced by another backend.
                if (profile.is_denied(anchor.kind))
                {
                    result.status = AnchorStatus::Failed;
                    return result;
                }

                if (evidence_module_is_scope(anchor.kind) && !scope_is_single_allocation(scope))
                {
                    return failed_anchor_result(anchor);
                }

                // Capture the owner before the walk. The witness then publishes the identity that produced the value,
                // not the identity present at return. An ExportName captures its own effective module below.
                ResolutionOwnerKeys owner_keys;
                owner_keys.requires_single_allocation = evidence_module_is_scope(anchor.kind);
                if (evidence_module_is_scope(anchor.kind))
                {
                    owner_keys.add_evidence(capture_scope_owner_key(scope));
                }
                // A Quorum owns no direct evidence. It carries the key from each member that casts a vote.
                std::vector<OwnerKey> member_keys;
                Region named_export_region{};
                OwnerKey named_export_owner{};

                switch (anchor.kind)
                {
                case AnchorKind::VtableIdentity:
                {
                    const std::optional<Address> discovered =
                        DetourModKit::rtti::vtable_for_type(anchor.mangled, scope);
                    if (discovered)
                    {
                        owner_keys.value = capture_value_owner(anchor, static_cast<std::int64_t>(discovered->raw()));
                        commit_resolved(anchor, result, static_cast<std::int64_t>(discovered->raw()));
                    }
                    else
                    {
                        result.status = AnchorStatus::Failed;
                    }
                    break;
                }
                case AnchorKind::RipGlobal:
                {
                    if (anchor.pages != scan::Pages::Readable && anchor.pages != scan::Pages::Executable)
                    {
                        return failed_anchor_result(anchor);
                    }
                    // The cascade selects Direct or RIP-relative per candidate. It also applies the profile order.
                    // Pages defaults to Readable. If every rung anchors on an image instruction, select Executable. A
                    // data-page byte twin then cannot alias the site.
                    const scan::ScanRequest request{
                        .ladder = anchor.site,
                        .label = anchor.label,
                        .scope = scope,
                        .order = profile.candidate_order,
                        .pages = anchor.pages,
                    };
                    const Result<detail::ResolvedScanHit> discovered = detail::resolve_scan_with_provenance(request);
                    if (discovered)
                    {
                        owner_keys.value =
                            capture_value_owner(anchor, static_cast<std::int64_t>(discovered->hit.address.raw()));
                        resolved_source = physical_source_of(discovered->hit.winning_mode);
                        resolved_evidence = discovered->hit.evidence;
                        resolved_winning_span = discovered->match_span;
                        if (provenance != nullptr)
                        {
                            provenance->add(discovered->physical_source);
                        }
                        commit_resolved(anchor, result, static_cast<std::int64_t>(discovered->hit.address.raw()));
                    }
                    else
                    {
                        result.status = AnchorStatus::Failed;
                    }
                    break;
                }
                case AnchorKind::CodeOperand:
                {
                    if (!valid_operand_kind(anchor.operand_kind) ||
                        !detail::valid_code_constant_byte_width(anchor.byte_width) ||
                        !valid_candidate_order(profile.candidate_order))
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }
                    // read_code_constant has no order parameter. Create a local ladder in profile order before the
                    // call.
                    std::vector<scan::Candidate> ordered_site;
                    const scan::CodeConstant code_constant{
                        .site = profiled_candidates(profile, anchor.site, ordered_site),
                        .kind = anchor.operand_kind,
                        .operand_index = anchor.operand_index,
                        .byte_width = anchor.byte_width,
                    };
                    const Result<detail::ResolvedCodeConstant> discovered =
                        detail::read_code_constant_with_provenance(code_constant, scope);
                    if (discovered)
                    {
                        owner_keys.value = capture_value_owner(anchor, discovered->value);
                        if (provenance != nullptr)
                        {
                            provenance->add(discovered->instruction_span);
                            provenance->add(discovered->physical_source);
                        }
                        commit_resolved(anchor, result, discovered->value);
                    }
                    else
                    {
                        result.status = AnchorStatus::Failed;
                    }
                    break;
                }
                case AnchorKind::StringXref:
                {
                    if (!valid_string_encoding(anchor.xref_encoding) || !valid_xref_return(anchor.xref_return))
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }
                    // Anchor on an immutable string literal, then resolve its reference site. An absent literal,
                    // duplicate literal, or literal without a reference fails closed.
                    scan::StringRefQuery query{};
                    query.text = anchor.xref_text;
                    query.encoding = anchor.xref_encoding;
                    query.require_terminator = anchor.xref_require_terminator;
                    query.return_mode = anchor.xref_return;
                    query.broad_match = anchor.xref_broad_match;
                    query = apply_profile(profile, query);
                    Region discovered_span{};
                    const Result<Address> discovered =
                        detail::find_string_xref_with_provenance(query, scope, discovered_span);
                    if (discovered)
                    {
                        owner_keys.value = capture_value_owner(anchor, static_cast<std::int64_t>(discovered->raw()));
                        if (provenance != nullptr)
                        {
                            provenance->add(discovered_span);
                        }
                        commit_resolved(anchor, result, static_cast<std::int64_t>(discovered->raw()));
                    }
                    else
                    {
                        result.status = AnchorStatus::Failed;
                    }
                    break;
                }
                case AnchorKind::ExportName:
                {
                    // Resolve a named export through the module EAT. An explicit export_module uses module_named. An
                    // empty export_module uses the passed scope. An unloaded module, absent or forwarded export, or
                    // corrupt export directory fails closed.
                    const Region module =
                        anchor.export_module.empty() ? scope : Region::module_named(anchor.export_module);
                    named_export_region = module;
#if defined(DMK_ENABLE_TEST_SEAMS)
                    if (auto *const hook = DetourModKit::detail::g_anchor_after_named_export_lookup_test_hook)
                    {
                        hook();
                    }
#endif
                    named_export_owner = capture_owner_key(module);
                    owner_keys.add_evidence(named_export_owner);
                    if (!named_export_owner_current(anchor, named_export_region, named_export_owner))
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }
                    DetourModKit::detail::ExportResolution discovered_export;
                    const Result<Address> discovered = DetourModKit::detail::resolve_export_with_provenance(
                        anchor.export_name, module, discovered_export);
                    if (discovered)
                    {
                        owner_keys.value = capture_value_owner(anchor, static_cast<std::int64_t>(discovered->raw()));
                        if (provenance != nullptr)
                        {
                            provenance->add(discovered_export);
                        }
                        commit_resolved(anchor, result, static_cast<std::int64_t>(discovered->raw()));
                    }
                    else
                    {
                        result.status = AnchorStatus::Failed;
                    }
                    break;
                }
                case AnchorKind::Manual:
                    // A pinned literal always "resolves". A report flags its kind as at risk. The default path skips
                    // the validator. validate_manual selects the fail-closed validator path.
                    if (anchor.validate_manual)
                    {
                        owner_keys.value = capture_value_owner(anchor, anchor.manual_value);
                        commit_resolved(anchor, result, anchor.manual_value);
                    }
                    else
                    {
                        result.value = anchor.manual_value;
                        result.status = AnchorStatus::Resolved;
                    }
                    break;
                case AnchorKind::CallArgHome:
                    // This kind is reserved for a future prologue-dataflow backend. No resolver exists yet.
                    result.status = AnchorStatus::Unsupported;
                    break;
                case AnchorKind::Quorum:
                {
                    // An N-of-M vote survives a patch that breaks some signals if N still agree. Fail closed on a
                    // malformed declaration.
                    if (!valid_quorum_match(anchor.quorum_match))
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }
                    const std::span<const Anchor *const> members = anchor.quorum_members;

                    // A quorum needs at least two members. A null or nested-Quorum member is malformed. This rule
                    // limits recursion to one level.
                    if (members.size() < 2)
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }
                    const bool malformed_member =
                        std::any_of(members.begin(), members.end(), [](const Anchor *member) noexcept
                                    { return member == nullptr || member->kind == AnchorKind::Quorum; });
                    if (malformed_member)
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }

                    // An effective N of zero means unanimous. An explicit N below two or above the member count fails
                    // closed rather than silently degrade to a single signal.
                    const std::size_t threshold =
                        (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
                    if (threshold < 2 || threshold > members.size())
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }

                    // Independence has two sources. Check declaration evidence here before the recursive resolves.
                    // Check evidence from resolved sites afterward.
                    if (!internal::quorum_members_pairwise_independent(members))
                    {
                        result.status = AnchorStatus::QuorumNotIndependent;
                        break;
                    }

                    // Resolve each member with the same profile so denied kinds and broad defaults propagate. A failed
                    // member contributes no vote. This behavior gives N-of-M its fault tolerance.
                    std::vector<std::int64_t> votes;
                    votes.reserve(members.size());
                    std::vector<PhysicalProvenance> vote_provenance;
                    vote_provenance.reserve(members.size());
                    bool physical_dependency = false;
                    member_keys.reserve(members.size() * 2);
                    for (const Anchor *member : members)
                    {
                        PhysicalProvenance member_provenance;
                        ResolutionOwnerKeys member_owner_keys;
                        const ResolvedAnchor resolved_member = resolve_with_profile_impl(
                            *member, profile, scope, &member_provenance, &member_owner_keys, nullptr);
                        if (resolved_member.status == AnchorStatus::Resolved)
                        {
                            physical_dependency =
                                physical_dependency || std::any_of(vote_provenance.begin(), vote_provenance.end(),
                                                                   [&](const PhysicalProvenance &existing) noexcept
                                                                   { return member_provenance.intersects(existing); });
                            votes.push_back(resolved_member.value);
                            vote_provenance.push_back(member_provenance);
                            // Only a member that casts a vote supplies evidence for corroboration.
                            append_owner_keys(member_keys, member_owner_keys);
                            owner_keys.requires_single_allocation =
                                owner_keys.requires_single_allocation || member_owner_keys.requires_single_allocation;
                        }
                    }
                    if (physical_dependency)
                    {
                        result.status = AnchorStatus::QuorumNotIndependent;
                        break;
                    }

                    // Collect every distinct vote value that anchors a cluster of at least N votes. Declaration order
                    // never selects among these values.
                    std::vector<std::int64_t> qualifying;
                    for (const std::int64_t center : votes)
                    {
                        if (std::find(qualifying.begin(), qualifying.end(), center) != qualifying.end())
                        {
                            continue;
                        }
                        if (votes_agreeing_with(center, votes, anchor.quorum_match, anchor.quorum_tolerance) >=
                            threshold)
                        {
                            qualifying.push_back(center);
                        }
                    }
                    if (qualifying.empty())
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }
                    // If two qualified centers disagree, separate clusters cleared N and no single value has
                    // corroboration. This also catches the non-transitive WithinTolerance overlap at 0/4/8 with 4.
                    const bool ambiguous = std::any_of(
                        qualifying.begin(), qualifying.end(),
                        [&](std::int64_t first) noexcept
                        {
                            return std::any_of(qualifying.begin(), qualifying.end(),
                                               [&](std::int64_t second) noexcept
                                               {
                                                   return !quorum_values_agree(first, second, anchor.quorum_match,
                                                                               anchor.quorum_tolerance);
                                               });
                        });
                    if (ambiguous)
                    {
                        result.status = AnchorStatus::QuorumAmbiguous;
                        break;
                    }
                    // For one coherent cluster, commit its canonical center through the shared path. The center is the
                    // smallest qualified value. The shared path invokes the Quorum validator.
                    const std::int64_t accepted = *std::min_element(qualifying.begin(), qualifying.end());
                    owner_keys.value = capture_value_owner(anchor, accepted);
                    commit_resolved(anchor, result, accepted);
                    break;
                }
                case AnchorKind::Unset:
                    // An Unset kind on a default-constructed anchor fails closed rather than invent a value.
                    result.status = AnchorStatus::Failed;
                    break;
                }

                // An out-of-range AnchorKind reaches here with the initial non-terminal Unresolved. Normalize it to
                // Failed so a resolved report never leaves an entry Unresolved.
                if (result.status == AnchorStatus::Unresolved)
                {
                    result.status = AnchorStatus::Failed;
                }
                // Stamp the typed domain only on a committed value: the single choke point every resolved path
                // reaches. A failed entry keeps the fail-closed ResultDomain::Unknown default.
                if (result.status == AnchorStatus::Resolved)
                {
                    result.domain = declared_domain(anchor);
                    // A CodeSite claim is trustworthy only on an executable page. A code-site kind at a non-executable
                    // data address downgrades to DataAddress. The downgrade denies a mid-hook on a data export.
                    if (result.domain == ResultDomain::CodeSite &&
                        !DetourModKit::detail::is_executable_address(static_cast<std::uintptr_t>(result.value)))
                    {
                        result.domain = ResultDomain::DataAddress;
                    }
                    // A truncated or unauthoritative sweep cannot reach Resolved. Address-domain values copy the owner
                    // identity captured before validation. Scalars have no owner image.
                    result.witness.completeness = WitnessCompleteness::Complete;
                    result.witness.source = resolved_source;
                    result.witness.evidence = resolved_evidence;
                    if (anchor.kind == AnchorKind::CodeOperand)
                    {
                        result.witness.operand_kind = anchor.operand_kind;
                    }
                    if (is_address_domain(result.domain))
                    {
                        result.witness.image = owner_keys.value.identity;
                    }
                }
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (result.status == AnchorStatus::Resolved)
                {
                    if (auto *const hook = DetourModKit::detail::g_anchor_after_witness_test_hook)
                    {
                        hook();
                    }
                }
#endif

                // Re-check after every validator, domain probe, and witness write. Temporal drift overrides quorum
                // diagnostics: mixed generations are a failed trust transaction.
                if (!evidence_images_coherent(owner_keys, member_keys))
                {
                    return failed_anchor_result(anchor);
                }
                if (owner_keys.requires_single_allocation && !scope_is_single_allocation(scope))
                {
                    return failed_anchor_result(anchor);
                }
                if (!named_export_owner_current(anchor, named_export_region, named_export_owner))
                {
                    return failed_anchor_result(anchor);
                }
                if (owner_keys_out != nullptr)
                {
                    *owner_keys_out = owner_keys;
                }
                if (winning_span_out != nullptr)
                {
                    *winning_span_out = resolved_winning_span;
                }
                return result;
            }
        } // namespace

        ResolvedAnchor resolve_with_profile(const Anchor &anchor, const ScanProfile &profile, Region scope)
        {
            return resolve_with_profile_impl(anchor, profile, scope, nullptr, nullptr, nullptr);
        }

        namespace internal
        {
            ResolvedAnchor resolve_with_winning_span(const Anchor &anchor, Region scope, Region &winning_span)
            {
                return resolve_with_profile_impl(anchor, ScanProfile{}, scope, nullptr, nullptr, &winning_span);
            }
        } // namespace internal

        ResolvedAnchor resolve(const Anchor &anchor, Region scope)
        {
            // An empty profile denies nothing and widens nothing, so this is exactly the un-profiled resolution.
            return resolve_with_profile(anchor, ScanProfile{}, scope);
        }

        std::size_t resolve_all(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = resolve(anchors[i], scope);
            }
            return count;
        }

        std::size_t resolve_all_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out, Region scope,
                                         std::size_t max_workers)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            const std::vector<ResolvedAnchor> results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
                anchors.first(count), max_workers,
                [scope](const Anchor &anchor) -> ResolvedAnchor { return resolve(anchor, scope); },
                [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = results[i];
            }
            return count;
        }

        std::size_t resolve_all_with_profile(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                             const ScanProfile &profile, Region scope)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = resolve_with_profile(anchors[i], profile, scope);
            }
            return count;
        }

        std::size_t resolve_all_with_profile_parallel(std::span<const Anchor> anchors, std::span<ResolvedAnchor> out,
                                                      const ScanProfile &profile, Region scope, std::size_t max_workers)
        {
            const std::size_t count = (anchors.size() < out.size()) ? anchors.size() : out.size();
            const std::vector<ResolvedAnchor> results = DetourModKit::detail::run_fork_join<Anchor, ResolvedAnchor>(
                anchors.first(count), max_workers, [&profile, scope](const Anchor &anchor) -> ResolvedAnchor
                { return resolve_with_profile(anchor, profile, scope); },
                [](const Anchor &anchor) noexcept -> ResolvedAnchor { return failed_anchor_result(anchor); });

            for (std::size_t i = 0; i < count; ++i)
            {
                out[i] = results[i];
            }
            return count;
        }

        ResultDomain declared_domain(const Anchor &anchor) noexcept
        {
            switch (anchor.kind)
            {
            case AnchorKind::VtableIdentity:
                return ResultDomain::VtableAddress;
            case AnchorKind::CodeOperand:
                if (!valid_operand_kind(anchor.operand_kind) ||
                    !detail::valid_code_constant_byte_width(anchor.byte_width))
                {
                    return ResultDomain::Unknown;
                }
                return ResultDomain::Scalar;
            case AnchorKind::Manual:
                // A decoded operand value and a pinned literal are constants, not addresses to write through.
                return ResultDomain::Scalar;
            case AnchorKind::StringXref:
                if (!valid_string_encoding(anchor.xref_encoding) || !valid_xref_return(anchor.xref_return))
                {
                    return ResultDomain::Unknown;
                }
                // The instruction or its parent function is code. A pointer-slot return is a data slot.
                if (anchor.xref_return == scan::XrefReturn::StringPointerSlot)
                {
                    return ResultDomain::DataAddress;
                }
                return ResultDomain::CodeSite;
            case AnchorKind::ExportName:
                return ResultDomain::CodeSite;
            case AnchorKind::RipGlobal:
                if (anchor.pages != scan::Pages::Readable && anchor.pages != scan::Pages::Executable)
                {
                    return ResultDomain::Unknown;
                }
                // The pages field states the author contract. Executable narrows the cascade to image instruction
                // sites. The default Readable admits a data-page global.
                if (anchor.pages == scan::Pages::Executable)
                {
                    return ResultDomain::CodeSite;
                }
                return ResultDomain::DataAddress;
            case AnchorKind::Quorum:
            {
                if (!valid_quorum_match(anchor.quorum_match))
                {
                    return ResultDomain::Unknown;
                }
                // The quorum domain is the one specific non-Scalar domain on which its members agree. A Manual or
                // Scalar member is a wildcard corroborator. Different specific domains are ambiguous.
                // A nested Quorum member is malformed (rejected at resolve), so it is skipped, not recursed into.
                ResultDomain domain = ResultDomain::Scalar;
                for (const Anchor *member : anchor.quorum_members)
                {
                    if (member == nullptr || member->kind == AnchorKind::Quorum)
                    {
                        continue;
                    }
                    const ResultDomain member_domain = declared_domain(*member);
                    if (member_domain == ResultDomain::Scalar || member_domain == ResultDomain::Unknown)
                    {
                        continue;
                    }
                    if (domain == ResultDomain::Scalar)
                    {
                        domain = member_domain;
                    }
                    else if (domain != member_domain)
                    {
                        return ResultDomain::Unknown;
                    }
                }
                return domain;
            }
            case AnchorKind::CallArgHome:
            case AnchorKind::Unset:
                return ResultDomain::Unknown;
            }
            return ResultDomain::Unknown;
        }
    } // namespace anchor
} // namespace DetourModKit
