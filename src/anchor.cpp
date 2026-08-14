/**
 * @file anchor.cpp
 * @brief The declarative anchor registry: dispatches each anchor kind to its v4 backend and reports drift uniformly.
 * @details Five kinds use one self-heal backend and fail closed. Manual has no backend. CallArgHome has no resolver.
 *          Unset fails closed. Quorum combines independent member results. This layer maps each typed backend error
 *          to AnchorStatus. It also applies the optional validator and per-game ScanProfile defaults.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/rtti.hpp"

#include "fork_join.hpp"
#include "internal/anchor_resolution.hpp"
#include "internal/export_resolution.hpp"
#include "internal/scan_pages.hpp"
#include "internal/scan_shared.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cmath>
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

            // Fail-closed agreement test. Unsigned subtraction converts a negative tolerance to a huge bound that
            // accepts almost any gap, so reject it first.
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

            // Fail-closed range checks for the per-kind safety enums: a hand-built out-of-range enum reports
            // AnchorStatus::Failed at this boundary and can never silently select a resolution mode.
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

            // The canonical independence-evidence atoms, defined below with the other fingerprint machinery.
            void collect_independence_atoms(const Anchor &anchor, std::vector<std::uint64_t> &out);

            // Returns true when two resolvable sub-anchors can decode one site. Such anchors share at least one
            // evidence atom, so one physical signal can satisfy both. Set intersection catches partial overlap.
            // Two ladders with one shared rung can land on one site and cast two votes. collect_independence_atoms
            // defines the canonical axes. An atom collision rejects a valid pair and therefore fails closed.
            [[nodiscard]] bool same_backend_config(const Anchor &a, const Anchor &b)
            {
                std::vector<std::uint64_t> atoms_a;
                collect_independence_atoms(a, atoms_a);
                std::vector<std::uint64_t> atoms_b;
                collect_independence_atoms(b, atoms_b);
                for (const std::uint64_t atom_a : atoms_a)
                {
                    for (const std::uint64_t atom_b : atoms_b)
                    {
                        if (atom_a == atom_b)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            // Fail-closed independence gate before agreement. The same Anchor object, two Manual literals, or one
            // shared backend config are not independent. Two Manual values prove no live-image corroboration.
            [[nodiscard]] bool quorum_sub_anchors_independent(const Anchor &a, const Anchor &b)
            {
                if (&a == &b)
                {
                    return false;
                }
                if (a.kind == AnchorKind::Manual && b.kind == AnchorKind::Manual)
                {
                    return false;
                }
                // Two same-name ExportName members are one witness if the modules match or either module is empty.
                // The empty module can resolve inside the named module. The static atom cannot detect this overlap.
                if (a.kind == AnchorKind::ExportName && b.kind == AnchorKind::ExportName &&
                    a.export_name == b.export_name &&
                    (a.export_module.empty() || b.export_module.empty() || a.export_module == b.export_module))
                {
                    return false;
                }
                return !same_backend_config(a, b);
            }

            // Every pair must provide independent evidence. One dependent pair can count one site twice. This rule
            // limits WithinTolerance to content-independent members. It prevents a near-value cluster from two
            // adjacent reads of one site. Complexity is O(M^2) for the small declared M.
            [[nodiscard]] bool quorum_members_pairwise_independent(std::span<const Anchor *const> members)
            {
                for (std::size_t i = 0; i < members.size(); ++i)
                {
                    for (std::size_t j = i + 1; j < members.size(); ++j)
                    {
                        if (!quorum_sub_anchors_independent(*members[i], *members[j]))
                        {
                            return false;
                        }
                    }
                }
                return true;
            }

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
                // Opt-in required-validator policy for backend-resolved targets. Manual and Quorum are exempt: a
                // pinned literal is not a resolved target, and a Quorum's corroboration is already the verification.
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

            [[nodiscard]] double clamped_gate_ratio(double ratio) noexcept
            {
                if (std::isnan(ratio))
                {
                    return 1.0;
                }
                if (ratio < 0.0)
                {
                    return 0.0;
                }
                if (ratio > 1.0)
                {
                    return 1.0;
                }
                return ratio;
            }

            // FNV-1a 64 hashes evidence for anchor_fingerprint. Results stay stable across runs and builds. Integers
            // use least-significant-byte order. Every variable-length field has a length prefix.
            inline constexpr std::uint64_t FNV1A64_OFFSET = 14695981039346656037ULL;
            inline constexpr std::uint64_t FNV1A64_PRIME = 1099511628211ULL;

            [[nodiscard]] std::uint64_t fnv1a_byte(std::uint64_t hash, std::uint8_t value) noexcept
            {
                return (hash ^ value) * FNV1A64_PRIME;
            }

            // Widen to u64 before each shift so a 1-byte type never hits a shift-width edge case.
            template <typename T> [[nodiscard]] std::uint64_t fnv1a_int(std::uint64_t hash, T value) noexcept
            {
                auto bits = static_cast<std::uint64_t>(static_cast<std::make_unsigned_t<T>>(value));
                for (std::size_t i = 0; i < sizeof(T); ++i)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(bits & 0xFFu));
                    bits >>= 8;
                }
                return hash;
            }

            // Prefixes each string field with its length so adjacent fields never alias.
            [[nodiscard]] std::uint64_t fnv1a_field(std::uint64_t hash, std::string_view field) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(field.size()));
                for (const char c : field)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(c));
                }
                return hash;
            }

            // Uses ASCII case-insensitive module basenames. Case variants of one DLL must not cast independent export
            // votes.
            [[nodiscard]] std::uint64_t fnv1a_module_field(std::uint64_t hash, std::string_view module_name) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(module_name.size()));
                for (const char c : module_name)
                {
                    const auto byte = static_cast<std::uint8_t>(c);
                    const std::uint8_t folded =
                        (byte >= static_cast<std::uint8_t>('A') && byte <= static_cast<std::uint8_t>('Z'))
                            ? static_cast<std::uint8_t>(byte + ('a' - 'A'))
                            : byte;
                    hash = fnv1a_byte(hash, folded);
                }
                return hash;
            }

            // Length-prefixed raw-byte field for a compiled Pattern's bytes / mask spans.
            [[nodiscard]] std::uint64_t fnv1a_bytes(std::uint64_t hash, std::span<const std::byte> data) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(data.size()));
                for (const std::byte b : data)
                {
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(b));
                }
                return hash;
            }

            // Folds the bounded-jump gap structure. bytes()/mask() carry only fixed segments. Without gap data,
            // patterns that differ only by variable gaps share a fingerprint. Jump-free patterns retain their prior
            // fingerprint.
            [[nodiscard]] std::uint64_t fnv1a_pattern_jumps(std::uint64_t hash, const scan::Pattern &pattern) noexcept
            {
                const detail::PatternBuffer &buffer = detail::pattern_buffer(pattern);
                if (buffer.jump_count == 0)
                {
                    return hash;
                }
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jump_count));
                for (std::size_t index = 0; index < buffer.jump_count; ++index)
                {
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jumps[index].position));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jumps[index].min_skip));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(buffer.jumps[index].max_skip));
                }
                return hash;
            }

            // Hashes one candidate's address-independent content. It includes compiled bytes, mask, offset, and decode
            // parameters for byte tiers. It includes owned name, literal, and shape flags for text tiers.
            [[nodiscard]] std::uint64_t fnv1a_candidate(std::uint64_t hash, const scan::Candidate &candidate) noexcept
            {
                hash = fnv1a_byte(hash, static_cast<std::uint8_t>(candidate.mode()));
                switch (candidate.mode())
                {
                case scan::Mode::Direct:
                {
                    const scan::DirectPattern &direct = *candidate.as_direct();
                    hash = fnv1a_bytes(hash, direct.pattern.bytes());
                    hash = fnv1a_bytes(hash, direct.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(direct.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(direct.walk_back));
                    hash = fnv1a_pattern_jumps(hash, direct.pattern);
                    break;
                }
                case scan::Mode::RipRelative:
                {
                    const scan::RipRelativePattern &rip = *candidate.as_rip_relative();
                    hash = fnv1a_bytes(hash, rip.pattern.bytes());
                    hash = fnv1a_bytes(hash, rip.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(rip.displacement_at));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.instruction_length));
                    hash = fnv1a_pattern_jumps(hash, rip.pattern);
                    break;
                }
                case scan::Mode::RttiVtable:
                    hash = fnv1a_field(hash, candidate.as_rtti_vtable()->mangled);
                    break;
                case scan::Mode::StringXref:
                {
                    const scan::StringXref &xref = *candidate.as_string_xref();
                    hash = fnv1a_field(hash, xref.text);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(xref.encoding));
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(xref.return_mode));
                    hash = fnv1a_byte(hash, xref.require_terminator ? 1U : 0U);
                    hash = fnv1a_byte(hash, xref.broad_match ? 1U : 0U);
                    break;
                }
                }
                return hash;
            }

            [[nodiscard]] std::uint64_t fnv1a_cascade(std::uint64_t hash,
                                                      std::span<const scan::Candidate> site) noexcept
            {
                hash = fnv1a_int(hash, static_cast<std::uint64_t>(site.size()));
                for (const scan::Candidate &candidate : site)
                {
                    hash = fnv1a_candidate(hash, candidate);
                }
                return hash;
            }

            // Hashes one anchor's evidence without quorum recursion. If a malformed sub-anchor sends Quorum here,
            // only its kind contributes. This limits recursion to one level.
            [[nodiscard]] std::uint64_t fingerprint_evidence(const Anchor &anchor) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(anchor.kind));
                switch (anchor.kind)
                {
                case AnchorKind::VtableIdentity:
                    hash = fnv1a_field(hash, anchor.mangled);
                    break;
                case AnchorKind::RipGlobal:
                    hash = fnv1a_cascade(hash, anchor.site);
                    // Preserve legacy fingerprints for the default Readable policy. Treat any other page policy as a
                    // declarative signature change that a persisted baseline can detect.
                    if (anchor.pages != scan::Pages::Readable)
                    {
                        hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.pages));
                    }
                    break;
                case AnchorKind::CodeOperand:
                    hash = fnv1a_cascade(hash, anchor.site);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.operand_kind));
                    hash = fnv1a_byte(hash, anchor.operand_index);
                    hash = fnv1a_byte(hash, anchor.byte_width);
                    break;
                case AnchorKind::StringXref:
                    hash = fnv1a_field(hash, anchor.xref_text);
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_encoding));
                    hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.xref_return));
                    hash = fnv1a_byte(hash, anchor.xref_require_terminator ? 1U : 0U);
                    hash = fnv1a_byte(hash, anchor.xref_broad_match ? 1U : 0U);
                    break;
                case AnchorKind::ExportName:
                    // The module and export name are the whole declarative signature.
                    hash = fnv1a_field(hash, anchor.export_module);
                    hash = fnv1a_field(hash, anchor.export_name);
                    break;
                case AnchorKind::Manual:
                    hash = fnv1a_int(hash, anchor.manual_value);
                    break;
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                case AnchorKind::Unset:
                    // No address-independent evidence beyond the kind byte already folded above.
                    break;
                }
                return hash;
            }

            // Independence evidence asks whether two anchors can decode one site. Drift evidence asks whether a
            // declaration changed. Each anchor becomes a set of site evidence atoms. The independence model drops
            // scan policy because a facet changes the sweep, not the literal. Policy variants of one site count as
            // one signal. The model also drops the AnchorKind wrapper. A flat StringXref and a one-rung RipGlobal over
            // the same literal resolve one site. EvidenceClass, rather than AnchorKind or scan::Mode, tags each atom.
            enum class EvidenceClass : std::uint8_t
            {
                ByteDirect = 1,
                ByteRip = 2,
                Vtable = 3,
                String = 4,
                Manual = 5,
                Empty = 6,
                Export = 7,
            };

            // A located literal uses its bytes and storage format as identity. Utf8 "foo" and Utf16le "foo" are
            // different image literals. Scan facets are not evidence.
            [[nodiscard]] std::uint64_t string_evidence_atom(std::string_view text,
                                                             scan::StringEncoding encoding) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::String));
                hash = fnv1a_field(hash, text);
                return fnv1a_byte(hash, static_cast<std::uint8_t>(encoding));
            }

            // A vtable identity's evidence: its mangled type name.
            [[nodiscard]] std::uint64_t vtable_evidence_atom(std::string_view mangled) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Vtable));
                return fnv1a_field(hash, mangled);
            }

            // A named export uses its declared module and export name as identity. The live table decides which names
            // alias, so backend provenance resolves aliases later. Use the declared module name, not a resolved base.
            // A base key collapses distinct unloaded modules onto one empty base. quorum_sub_anchors_independent
            // catches the empty and explicit module overlap.
            [[nodiscard]] std::uint64_t export_evidence_atom(std::string_view module_name,
                                                             std::string_view export_name) noexcept
            {
                std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Export));
                hash = fnv1a_module_field(hash, module_name);
                return fnv1a_field(hash, export_name);
            }

            // Builds one candidate rung's site identity atom without kind or policy data. A byte tier keeps every field
            // that moves its address. A text tier reduces to its flat AnchorKind atom.
            [[nodiscard]] std::uint64_t candidate_evidence_atom(const scan::Candidate &candidate) noexcept
            {
                switch (candidate.mode())
                {
                case scan::Mode::Direct:
                {
                    const scan::DirectPattern &direct = *candidate.as_direct();
                    std::uint64_t hash =
                        fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::ByteDirect));
                    hash = fnv1a_bytes(hash, direct.pattern.bytes());
                    hash = fnv1a_bytes(hash, direct.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(direct.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(direct.walk_back));
                    return fnv1a_pattern_jumps(hash, direct.pattern);
                }
                case scan::Mode::RipRelative:
                {
                    const scan::RipRelativePattern &rip = *candidate.as_rip_relative();
                    std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::ByteRip));
                    hash = fnv1a_bytes(hash, rip.pattern.bytes());
                    hash = fnv1a_bytes(hash, rip.pattern.mask());
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.pattern.offset()));
                    hash = fnv1a_int(hash, static_cast<std::int64_t>(rip.displacement_at));
                    hash = fnv1a_int(hash, static_cast<std::uint64_t>(rip.instruction_length));
                    return fnv1a_pattern_jumps(hash, rip.pattern);
                }
                case scan::Mode::RttiVtable:
                    return vtable_evidence_atom(candidate.as_rtti_vtable()->mangled);
                case scan::Mode::StringXref:
                {
                    const scan::StringXref &xref = *candidate.as_string_xref();
                    return string_evidence_atom(xref.text, xref.encoding);
                }
                }
                return fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Empty));
            }

            // Collects one site evidence atom per resolvable rung, or one for a flat kind. Do not reuse the drift
            // fingerprint here. It keeps policy and order because a facet edit or reorder is signature drift.
            void collect_independence_atoms(const Anchor &anchor, std::vector<std::uint64_t> &out)
            {
                const std::size_t start = out.size();
                switch (anchor.kind)
                {
                case AnchorKind::VtableIdentity:
                    out.push_back(vtable_evidence_atom(anchor.mangled));
                    break;
                case AnchorKind::StringXref:
                    out.push_back(string_evidence_atom(anchor.xref_text, anchor.xref_encoding));
                    break;
                case AnchorKind::ExportName:
                    out.push_back(export_evidence_atom(anchor.export_module, anchor.export_name));
                    break;
                case AnchorKind::Manual:
                {
                    std::uint64_t atom = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Manual));
                    out.push_back(fnv1a_int(atom, anchor.manual_value));
                    break;
                }
                case AnchorKind::RipGlobal:
                case AnchorKind::CodeOperand:
                    // Both kinds resolve through a rung site, which defines the failure domain. Each rung contributes
                    // only its site atom. The atom deliberately omits a CodeOperand selector. Two selectors over one
                    // site form one witness.
                    for (const scan::Candidate &candidate : anchor.site)
                    {
                        out.push_back(candidate_evidence_atom(candidate));
                    }
                    break;
                case AnchorKind::CallArgHome:
                case AnchorKind::Quorum:
                case AnchorKind::Unset:
                    // No resolvable evidence exists. The post-switch guard contributes a kind-tagged Empty atom.
                    break;
                }
                if (out.size() == start)
                {
                    // Contribute one kind-tagged Empty atom so the set is never empty. Two degenerate anchors of the
                    // same kind remain dependent.
                    std::uint64_t atom = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(EvidenceClass::Empty));
                    out.push_back(fnv1a_byte(atom, static_cast<std::uint8_t>(anchor.kind)));
                }
            }

            constexpr std::uint64_t NULL_SUB_ANCHOR = 0;

            [[nodiscard]] std::uint64_t quorum_member_evidence(const Anchor *member) noexcept
            {
                return member != nullptr ? fingerprint_evidence(*member) : NULL_SUB_ANCHOR;
            }
        } // anonymous namespace

        scan::StringRefQuery apply_profile(const ScanProfile &profile, scan::StringRefQuery query) noexcept
        {
            // Widen-only policy. A per-anchor broad_match value stays set. The profile can enable broad mode but cannot
            // disable it.
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
                    // Reserved for a future prologue-dataflow backend. No resolver exists yet.
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

                    // Effective N: 0 means unanimous. An explicit N below 2 or above the member count fails closed
                    // rather than silently degrade to a single signal.
                    const std::size_t threshold =
                        (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
                    if (threshold < 2 || threshold > members.size())
                    {
                        result.status = AnchorStatus::Failed;
                        break;
                    }

                    // Independence has two sources. Check declaration evidence here before the recursive resolves.
                    // Check evidence from resolved sites afterward.
                    if (!quorum_members_pairwise_independent(members))
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
                    // A default-constructed anchor whose kind was never set: fail closed rather than invent a value.
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

        AnchorQuality assess_quality(std::span<const ResolvedAnchor> report) noexcept
        {
            AnchorQuality quality{};
            quality.total = report.size();
            for (const ResolvedAnchor &entry : report)
            {
                switch (entry.status)
                {
                case AnchorStatus::Resolved:
                    ++quality.resolved;
                    break;
                case AnchorStatus::Failed:
                    ++quality.failed;
                    break;
                case AnchorStatus::Unsupported:
                    ++quality.unsupported;
                    break;
                case AnchorStatus::QuorumNotIndependent:
                    ++quality.not_independent;
                    break;
                case AnchorStatus::QuorumAmbiguous:
                    // Committed no trusted value, so it is a failure alongside a backend miss.
                    ++quality.failed;
                    break;
                case AnchorStatus::Unresolved:
                    break;
                }
                // A pinned literal is at-risk regardless of status: it "resolves" but cannot self-heal across a patch.
                if (entry.kind == AnchorKind::Manual)
                {
                    ++quality.manual_at_risk;
                }
                // A corroborated quorum is the strongest evidence: N independent signals had to agree.
                if (entry.kind == AnchorKind::Quorum && entry.status == AnchorStatus::Resolved)
                {
                    ++quality.corroborated;
                }
            }
            return quality;
        }

        GateVerdict evaluate_gate(const AnchorQuality &quality, const GatePolicy &policy) noexcept
        {
            // The span overload always feeds a self-consistent summary, but the direct AnchorQuality overload is
            // public. If a caller supplies impossible counts, fail closed so an inflated resolved count cannot create
            // a healthy verdict.
            std::size_t accounted = 0;
            const auto count_fits = [&accounted, total = quality.total](std::size_t count) noexcept -> bool
            {
                if (count > total - accounted)
                {
                    return false;
                }
                accounted += count;
                return true;
            };
            if (!count_fits(quality.resolved) || !count_fits(quality.failed) || !count_fits(quality.unsupported) ||
                !count_fits(quality.not_independent))
            {
                return GateVerdict::Fail;
            }

            // QuorumNotIndependent counts as a failure alongside Failed for the cap: both mean a declared anchor
            // yielded no verified value. Check the hard cap before the ratio. A failure-heavy manifest then fails even
            // when its few resolved entries clear the ratio.
            if (quality.failed > policy.max_failed)
            {
                return GateVerdict::Fail;
            }
            const std::size_t remaining_failure_budget = policy.max_failed - quality.failed;
            if (quality.not_independent > remaining_failure_budget)
            {
                return GateVerdict::Fail;
            }

            // Resolvable excludes the Unsupported kind, which has no backend and can never heal. Every other unresolved
            // kind stays in the denominator. A partial result therefore reduces the ratio and fails closed.
            const std::size_t resolvable = quality.total - quality.unsupported;
            if (resolvable == 0)
            {
                // No assessable entry proves runtime health. An empty report or all-unsupported table must
                // not become a healthy Pass merely because no resolvable anchor contradicts it.
                return GateVerdict::Degraded;
            }

            // Clamp the ratio to [0, 1]. NaN becomes the strict default. This prevents an out-of-range value from
            // inversion of the comparison. Avoid division so the full-ratio case retains exact equality.
            const double ratio = clamped_gate_ratio(policy.min_resolved_ratio);
            if (static_cast<double>(quality.resolved) < ratio * static_cast<double>(resolvable))
            {
                return GateVerdict::Fail;
            }

            // A resolved Manual literal remains unable to self-heal. If policy requests it, surface this soft risk so
            // the caller can report silent manual offset drift after a patch.
            if (policy.manual_at_risk_degrades && quality.manual_at_risk > 0)
            {
                return GateVerdict::Degraded;
            }
            return GateVerdict::Pass;
        }

        GateVerdict evaluate_gate(std::span<const ResolvedAnchor> report, const GatePolicy &policy) noexcept
        {
            return evaluate_gate(assess_quality(report), policy);
        }

        std::uint64_t anchor_fingerprint(const Anchor &anchor) noexcept
        {
            if (anchor.kind != AnchorKind::Quorum)
            {
                return fingerprint_evidence(anchor);
            }

            // A quorum folds member evidence without order because the vote is symmetric. It also folds the effective
            // threshold and agreement policy. Member hashes use sorted order without allocation. A null member adds a
            // fixed sentinel.
            const std::span<const Anchor *const> members = anchor.quorum_members;

            std::uint64_t hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(AnchorKind::Quorum));
            hash = fnv1a_int(hash, static_cast<std::uint64_t>(members.size()));

            std::uint64_t previous = 0;
            bool have_previous = false;
            std::size_t emitted = 0;
            while (emitted < members.size())
            {
                std::uint64_t next = 0;
                bool found_next = false;
                for (const Anchor *member : members)
                {
                    const std::uint64_t evidence = quorum_member_evidence(member);
                    if (have_previous && evidence <= previous)
                    {
                        continue;
                    }
                    if (!found_next || evidence < next)
                    {
                        next = evidence;
                        found_next = true;
                    }
                }

                if (!found_next)
                {
                    break;
                }

                std::size_t duplicate_count = 0;
                for (const Anchor *member : members)
                {
                    if (quorum_member_evidence(member) == next)
                    {
                        ++duplicate_count;
                    }
                }
                for (std::size_t i = 0; i < duplicate_count; ++i)
                {
                    hash = fnv1a_int(hash, next);
                }

                previous = next;
                have_previous = true;
                emitted += duplicate_count;
            }
            const std::size_t effective_threshold =
                (anchor.quorum_threshold == 0) ? members.size() : anchor.quorum_threshold;
            hash = fnv1a_int(hash, static_cast<std::uint64_t>(effective_threshold));
            hash = fnv1a_byte(hash, static_cast<std::uint8_t>(anchor.quorum_match));
            hash = fnv1a_int(hash, anchor.quorum_tolerance);
            return hash;
        }

        std::uint64_t anchor_trust_fingerprint(const Anchor &anchor, scan::ImageIdentity scope_identity) noexcept
        {
            std::uint64_t hash = 0;
            if (anchor.kind == AnchorKind::ExportName)
            {
                // Bind the effective module by identity, not by the declared export_module text. An empty module from
                // scope and an explicit name for that module therefore fold to one key.
                hash = fnv1a_byte(FNV1A64_OFFSET, static_cast<std::uint8_t>(AnchorKind::ExportName));
                hash = fnv1a_field(hash, anchor.export_name);
            }
            else
            {
                hash = anchor_fingerprint(anchor);
            }
            // Fold the effective image identity last: a same-base remap changes it, while ASLR alone does not.
            return fnv1a_int(hash, scope_identity.token());
        }

        std::string_view anchor_status_to_string(AnchorStatus status) noexcept
        {
            switch (status)
            {
            case AnchorStatus::Unresolved:
                return "Unresolved";
            case AnchorStatus::Resolved:
                return "Resolved";
            case AnchorStatus::Failed:
                return "Failed";
            case AnchorStatus::Unsupported:
                return "Unsupported";
            case AnchorStatus::QuorumNotIndependent:
                return "QuorumNotIndependent";
            case AnchorStatus::QuorumAmbiguous:
                return "QuorumAmbiguous";
            }
            return "Unknown";
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

        std::string_view result_domain_to_string(ResultDomain domain) noexcept
        {
            switch (domain)
            {
            case ResultDomain::Unknown:
                return "Unknown";
            case ResultDomain::CodeSite:
                return "CodeSite";
            case ResultDomain::DataAddress:
                return "DataAddress";
            case ResultDomain::VtableAddress:
                return "VtableAddress";
            case ResultDomain::Scalar:
                return "Scalar";
            }
            return "Unknown";
        }

        std::string_view physical_source_to_string(PhysicalSource source) noexcept
        {
            switch (source)
            {
            case PhysicalSource::None:
                return "None";
            case PhysicalSource::ByteSignature:
                return "ByteSignature";
            case PhysicalSource::StringLiteral:
                return "StringLiteral";
            case PhysicalSource::TypeIdentity:
                return "TypeIdentity";
            case PhysicalSource::ExportTable:
                return "ExportTable";
            case PhysicalSource::CodeOperand:
                return "CodeOperand";
            case PhysicalSource::ManualPin:
                return "ManualPin";
            case PhysicalSource::Corroborated:
                return "Corroborated";
            }
            return "Unknown";
        }

        std::string_view gate_verdict_to_string(GateVerdict verdict) noexcept
        {
            switch (verdict)
            {
            case GateVerdict::Pass:
                return "Pass";
            case GateVerdict::Degraded:
                return "Degraded";
            case GateVerdict::Fail:
                return "Fail";
            }
            return "Unknown";
        }
    } // namespace anchor
} // namespace DetourModKit
