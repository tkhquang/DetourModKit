#ifndef DETOURMODKIT_MANIFEST_HPP
#define DETOURMODKIT_MANIFEST_HPP

/**
 * @file manifest.hpp
 * @brief Signature manifest: patch-fragile resolve contracts as editable data in its own INI, not the settings INI.
 * @warning `[B-100]` Never parse, compile, resolve, gate, or derive a scope under the loader lock. Pure value accessors
 *          on a compiled @ref Signature do not allocate or query the loader.
 */

#include "DetourModKit/anchor.hpp"
#include "DetourModKit/error.hpp"
#include "DetourModKit/region.hpp"
#include "DetourModKit/scan.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace DetourModKit
{
    // Binding::read_register needs only this declaration. Include hook.hpp to name a hook::Gpr value.
    namespace hook
    {
        enum class Gpr : std::uint8_t;
    }

    namespace manifest
    {
        namespace detail
        {
            class GateAccess;
        } // namespace detail

        /** @brief How a consumer interprets a resolved value. The consumer, not this module, acts on it. */
        enum class BindingKind : std::uint8_t
        {
            /// The resolved value is the target address, for example an inline-hook target or a global.
            Address,
            /// The resolved value is a chain base that the consumer walks through @ref Binding::offsets.
            PointerChain,
            /// The resolved value is a mid-hook site, where @ref hook::gpr reads @ref Binding::read_register.
            MidHookRegister,
            /** @brief The resolved value is a vtable base. Hook the slot at @ref Binding::vmt_index. */
            VmtMethod
        };

        /// The @ref Binding::xmm_index sentinel: the site reads a GPR, not an XMM lane.
        inline constexpr std::uint8_t XMM_INDEX_UNUSED = 0xFF;

        /** @brief How to read a resolved value. A field that @ref kind does not read is inert and must stay default. */
        struct Binding
        {
            /// How to interpret the resolved value.
            BindingKind kind = BindingKind::Address;
            /// PointerChain: one or more byte offsets walked from the resolved base with @ref memory::walk semantics.
            std::vector<std::ptrdiff_t> offsets;
            /// PointerChain: byte width of the final read (1, 2, 4, or 8), for example 4 for a float.
            std::uint8_t value_width = 8;
            /// MidHookRegister: the register that the mid-hook callback reads.
            hook::Gpr read_register{};
            /// MidHookRegister: XMM lane 0 through 15 for a float site, or @ref XMM_INDEX_UNUSED for a GPR value.
            std::uint8_t xmm_index = XMM_INDEX_UNUSED;
            /// VmtMethod: the zero-based vtable slot to hook, from 0 through 4095.
            std::size_t vmt_index = 0;
        };

        /** @brief One editable ladder rung for a @ref scan::Candidate. Resolution ignores the fields of other modes. */
        struct CandidateSpec
        {
            /// Human-readable rung name, carried into the winning @ref scan::Hit for diagnostics.
            std::string name;
            /// Which resolution strategy this rung uses.
            scan::Mode mode = scan::Mode::Direct;
            /// Direct / RipRelative: the AOB DSL string, for example "48 8B 05 ?? ?? ?? ??".
            std::string pattern;
            /// Direct: signed byte delta added to the match, where a negative value walks backward.
            std::ptrdiff_t walk_back = 0;
            /// RipRelative: byte offset from the match to the signed 4-byte displacement field.
            std::ptrdiff_t displacement_at = 0;
            /// RipRelative: total length of the referencing instruction (the next-IP base for the displacement).
            std::size_t instruction_length = 0;
            /// RttiVtable: the MSVC mangled type name, for example ".?AVCameraManager@@".
            std::string mangled;
            /// StringXref: same as @ref SignatureRecord::xref_text.
            std::string string_text;
            /// StringXref: same as @ref SignatureRecord::xref_encoding.
            scan::StringEncoding string_encoding = scan::StringEncoding::Utf8;
            /// StringXref: same as @ref SignatureRecord::xref_return.
            scan::XrefReturn string_return = scan::XrefReturn::ReferencingInstruction;
            /// StringXref: same as @ref SignatureRecord::xref_require_terminator.
            bool string_require_terminator = true;
            /// StringXref: same as @ref SignatureRecord::xref_broad_match.
            bool string_broad_match = false;
        };

        /**
         * @brief An owning, serializable @ref anchor::Anchor plus @ref Binding. Resolution ignores the fields of other
         *        kinds.
         */
        struct SignatureRecord
        {
            /// Stable merge and lookup key, for example "player.health", echoed into the drift report and gate result.
            std::string label;
            /// Which anchor backend resolves this signature (one of the six serializable kinds).
            anchor::AnchorKind kind = anchor::AnchorKind::RipGlobal;
            /** @brief The module basename for @ref Region::module_named. Empty resolves within the fallback scope. */
            std::string module;

            /// RipGlobal / CodeOperand: the candidate ladder that resolves to the address or the instruction site.
            std::vector<CandidateSpec> ladder;

            /// VtableIdentity: the MSVC mangled type name to resolve through the reverse-RTTI walk.
            std::string mangled;

            /// CodeOperand: whether to read an immediate or a memory-operand displacement.
            scan::OperandKind operand_kind = scan::OperandKind::Immediate;
            /// CodeOperand: index into the instruction's visible operands.
            std::uint8_t operand_index = 0;
            /// CodeOperand: 0 keeps the decoded value, and 1 through 8 narrows non-RIP low bytes and sign-extends.
            std::uint8_t byte_width = 0;

            /// StringXref: the exact literal content to anchor on (no quotes).
            std::string xref_text;
            /**
             * @brief StringXref: the literal's byte encoding. Utf16le, for a wchar_t literal, needs well-formed UTF-8
             *        that resolution converts to UTF-16LE. @ref parse, @ref Signature::compile, @ref Signature::adopt,
             *        and @ref serialize_checked reject malformed text. Utf8 evidence stays byte-transparent.
             */
            scan::StringEncoding xref_encoding = scan::StringEncoding::Utf8;
            /// StringXref: whether to return the referencing instruction, its enclosing function, or the pointer slot.
            scan::XrefReturn xref_return = scan::XrefReturn::ReferencingInstruction;
            /// StringXref: match a trailing NUL so a prefix of a longer literal is not matched.
            bool xref_require_terminator = true;
            /// StringXref: keep the lea/mov shape scan and add the broad Zydis sweep for rarer reference shapes.
            bool xref_broad_match = false;

            /// Manual: the pinned literal value, taken as-is.
            std::int64_t manual_value = 0;

            /** @brief In-memory only, never in a file: a post-resolve validator, as @ref anchor::Anchor::validator. */
            anchor::AnchorValidator validator = nullptr;
            /** @brief In-memory only: the @ref validator context. The borrowed pointee must outlive each resolve. */
            const void *validator_context = nullptr;
            /** @brief In-memory only: run @ref validator on a Manual anchor too, so the pinned literal is checked. */
            bool validate_manual = false;
            /// In-memory only: fail closed when a backend-resolvable anchor carries no @ref validator.
            bool require_validator = false;

            /// How the consumer interprets the resolved value.
            Binding binding{};

            /** @brief The @ref Signature::current_fingerprint baseline captured when authored, or 0 if none exists. */
            std::uint64_t expected_fingerprint = 0;

            /** @brief RipGlobal: page class of byte-tier rungs. If all rungs anchor on instructions, use Executable. */
            scan::Pages pages = scan::Pages::Readable;

            /** @brief ExportName: the exact, case-sensitive, undecorated export in @ref module, such as "Sleep". */
            std::string export_name;

            /** @brief The optional live-image baseline (file key `image_identity`) that the identity gates compare. */
            scan::ImageIdentity expected_image_identity{};

            /** @brief The optional winning-span content baseline, file key `winning_bytes` in lowercase hex. */
            scan::WinningEvidence expected_winning_bytes{};
        };

        /** @brief The drift verdict of one signature. */
        enum class FingerprintState : std::uint8_t
        {
            /// No baseline exists (@ref SignatureRecord::expected_fingerprint is 0), so drift is unknown.
            Unset,
            /// The live fingerprint equals the baseline.
            Match,
            /// The live fingerprint differs from the baseline.
            Drifted
        };

        /** @brief A compiled signature that owns its evidence. Build one with @ref compile or @ref adopt. */
        class Signature
        {
        public:
            /**
             * @brief Compiles a file record into a resolvable signature.
             * @return The Signature, or one of these errors:
             *         - BadPattern: a rung AOB that does not compile.
             *         - EmptyCandidates: a RipGlobal or CodeOperand record with no ladder.
             *         - InvalidArg: a Quorum, CallArgHome, or Unset kind, or empty required evidence of the record or
             *           of an RttiVtable or StringXref rung. It also means a ladder on a kind other than RipGlobal or
             *           CodeOperand, or an out-of-range persisted policy field such as CodeOperand byte_width. It also
             *           means a label or string field that cannot round-trip, or a nonzero image baseline with a zero
             *           size_of_image. It also means a truncated or over-long content baseline, Utf16le evidence that
             *           breaks the @ref SignatureRecord::xref_encoding rule, or a @ref Binding that breaks a field
             *           rule. It also means a RipRelative rung that @ref scan::Candidate::rip_relative rejects.
             * @details A record that meets several conditions returns the code of the first failed check.
             * @note Setup/control-plane only.
             */
            [[nodiscard]] static Result<Signature> compile(SignatureRecord record);

            /**
             * @brief Adopts an in-code @ref anchor::Anchor and copies its borrowed views, so it can outlive @p source.
             * @return The Signature, or InvalidArg for a @ref compile InvalidArg condition outside the ladder, or a
             *         RipGlobal or CodeOperand anchor without candidates. It checks each candidate only against the
             *         @ref SignatureRecord::xref_encoding rule.
             * @details For a RipGlobal or CodeOperand kind, the record holds each candidate as a rung. A byte rung
             *          holds its pattern in canonical AOB text, and a text rung holds its mangled name or string. A
             *          @ref compile of that record rebuilds the same candidates and fingerprint, which
             *          `ManifestAdoptTest.RenderedLadderCompilesToTheSameCandidates` proves. A candidate that
             *          @ref compile rejects makes @ref serialize_checked reject the record.
             * @note Setup/control-plane only.
             */
            [[nodiscard]] static Result<Signature> adopt(const anchor::Anchor &source);

            /**
             * @brief Resolves this signature through its anchor backend, fail-closed. See @ref SignatureRecord::module.
             * @note Setup/control-plane only (see @ref anchor::resolve).
             */
            [[nodiscard]] anchor::ResolvedAnchor resolve(Region fallback_scope = Region::host()) const;

            /**
             * @brief The scope: @ref Region::module_named for the record's module, or @ref Region::host for none.
             * @note Setup/control-plane only: queries the loader.
             */
            [[nodiscard]] Region scope() const noexcept;

            /**
             * @brief The live fingerprint: a hash of @ref anchor::anchor_fingerprint, @ref Binding, label, and module.
             *        It reads no game memory, so it is stable across runs and rebuilds on one platform.
             */
            [[nodiscard]] std::uint64_t current_fingerprint() const noexcept;

            /** @brief Compares @ref current_fingerprint to the record baseline. See @ref FingerprintState. */
            [[nodiscard]] FingerprintState fingerprint_state() const noexcept;

            /**
             * @brief Makes the live fingerprint the baseline after a verified repair. Persist @ref record to keep it.
             * @note Setup/control-plane only.
             */
            void recapture_fingerprint() noexcept;

            /**
             * @brief Re-resolves and recaptures the fingerprint, image identity, and winning-span content baselines.
             * @param fallback_scope The scope for a record that names no module. It must match the later gate scope.
             * @return Success, NoMatch if the signature does not resolve, or UnexpectedShape if the resolved rung
             *         witnesses no image or content span. Only a RipGlobal hit from a Direct or RipRelative rung can
             *         witness both, with at most @ref scan::MAX_MUTATION_WITNESS_BYTES of content.
             * @details Only this call captures live image and content baselines for @ref GatePolicy::mutation_strict. A
             *          failure keeps all three previous baselines. Persist @ref record to keep the new ones.
             * @note Setup/control-plane only.
             */
            [[nodiscard]] Result<void> recapture(Region fallback_scope = Region::host());

            /// The signature's stable key.
            [[nodiscard]] std::string_view label() const noexcept;
            /// Which anchor backend resolves this signature.
            [[nodiscard]] anchor::AnchorKind kind() const noexcept;
            /// The consumer-facing binding (register / offsets / vtable slot).
            [[nodiscard]] const Binding &binding() const noexcept;
            /// The owning record, for @ref serialize_checked after a recapture.
            [[nodiscard]] const SignatureRecord &record() const noexcept;

        private:
            friend class detail::GateAccess;

            // Only compile() and adopt() construct.
            Signature(SignatureRecord record, std::vector<scan::Candidate> ladder) noexcept;

            // A borrowed view of this object's storage. It is rebuilt per call and valid only for that call.
            [[nodiscard]] anchor::Anchor make_anchor() const noexcept;

            // Also returns the winning match span for the mutation gate.
            [[nodiscard]] anchor::ResolvedAnchor resolve_for_gate(Region fallback_scope, Region &winning_span) const;

            SignatureRecord m_record;
            std::vector<scan::Candidate> m_ladder;
        };

        /// The INI format version that this build reads and writes, bumped only for an incompatible format change.
        inline constexpr std::uint32_t SCHEMA_VERSION = 1;

        /** @brief The `[manifest]` metadata. Only an in-code change that breaks older manifests bumps @ref revision. */
        struct ManifestHeader
        {
            /// The format version that the file declares.
            std::uint32_t schema = SCHEMA_VERSION;
            /// The author's signature-contract epoch, or 0 if unversioned, compared only by @ref revision_compatible.
            std::uint32_t revision = 0;
        };

        /** @brief A parsed manifest: its @ref ManifestHeader plus the signature records in file order. */
        struct Manifest
        {
            /// The `[manifest]` metadata (schema and contract revision).
            ManifestHeader header{};
            /// The signatures, one per `[sig.<label>]` section, in file order.
            std::vector<SignatureRecord> records{};
        };

        /** @brief Parse and persistence caps. A violation returns SizeTooLarge and publishes no partial result. */
        struct ManifestLimits
        {
            /// Largest accepted encoded text size in bytes.
            std::size_t max_file_bytes{1u << 20};
            /// Largest accepted INI section count, by default sized to the default record and rung caps: 1 + 512 * 33.
            std::size_t max_sections{16897};
            /// Largest accepted number of keys within any one section.
            std::size_t max_keys_per_section{64};
            /// Largest accepted number of `[sig.<label>]` records.
            std::size_t max_records{512};
            /// Largest accepted number of candidate-ladder rungs on any one record.
            std::size_t max_rungs_per_record{32};
            /// Largest accepted size in bytes of any single string field or heredoc value.
            std::size_t max_field_bytes{64u << 10};
            /// Largest accepted sum of all decoded value bytes across the manifest.
            std::size_t max_total_decoded_bytes{4u << 20};

            /// Returns limits equal to a default-constructed @ref ManifestLimits.
            [[nodiscard]] static constexpr ManifestLimits conservative() noexcept { return ManifestLimits{}; }

            /** @brief Uncapped limits for a trusted authoring tool only. Grammar and semantic checks stay on. */
            [[nodiscard]] static constexpr ManifestLimits advanced() noexcept
            {
                // Parenthesized because public headers must compile with <windows.h>'s function-like max macro active.
                constexpr std::size_t MAX_VALUE = (std::numeric_limits<std::size_t>::max)();
                return ManifestLimits{
                    .max_file_bytes = MAX_VALUE,
                    .max_sections = MAX_VALUE,
                    .max_keys_per_section = MAX_VALUE,
                    .max_records = MAX_VALUE,
                    .max_rungs_per_record = MAX_VALUE,
                    .max_field_bytes = MAX_VALUE,
                    .max_total_decoded_bytes = MAX_VALUE,
                };
            }
        };

        /**
         * @brief Returns true if @p build_revision is 0, which opts out, or equals @ref ManifestHeader::revision. If it
         *        returns false, pass no file records to @ref overlay.
         */
        [[nodiscard]] bool revision_compatible(const ManifestHeader &header, std::uint32_t build_revision) noexcept;

        /**
         * @brief Parses manifest INI text. A failure rejects the whole manifest.
         * @return The @ref Manifest, OutOfMemory, or one of these errors:
         *         - MissingHeader: no `[manifest]` section, no `schema` key, or an unsupported schema.
         *         - MalformedLine: an unparsable line, field, or enum token, a noncomment key line without `=`, or an
         *           empty key. It also covers a non-canonical section or key spelling, a section that is neither
         *           `[manifest]` nor `sig.`-prefixed, and a key line before the first header. It also covers a key that
         *           its record's kind, binding kind, or rung mode does not read. It also covers a rung under a kind
         *           other than RipGlobal or CodeOperand, and Utf16le evidence that breaks the
         *           @ref SignatureRecord::xref_encoding rule.
         *         - ManifestIdentityCollision: a case-, whitespace-, or exactly-duplicated section, or a
         *           whitespace-variant or exactly-duplicated key. A miscased key returns MalformedLine instead.
         *         - ManifestFramingUnsafe: an unterminated `<<<` heredoc value, an opener with an empty tag, or a
         *           heredoc whose first body line is its terminator.
         *         - SizeTooLarge: encoded text, a section, key, field, record, rung, or aggregate over @p limits.
         * @details A missing optional key takes its default, so an absent `revision` is 0. A present key must parse, so
         *          a blank enum, numeric, boolean, or baseline value is MalformedLine. A blank `schema` is
         *          MissingHeader, and a blank `offsets` is an empty list. A blank string value reads as empty.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] Result<Manifest>
        parse(std::string_view text, const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Serializes a manifest to INI text that @ref parse reads back and @ref Signature::compile accepts.
         * @return The text, OutOfMemory, or one of these errors:
         *         - InvalidArg, EmptyCandidates, or BadPattern: a record that @ref Signature::compile rejects, with the
         *           code that compile returns.
         *         - ManifestIdentityCollision: two record labels that fold to one section, or a label that folds into
         *           another record's rung section.
         *         - SizeTooLarge: encoded text, a record, rung, field, or aggregate that exceeds @p limits.
         * @details A manifest that fails several checks returns the code of the first failed check. It writes
         *          `revision` only if non-zero, and `schema` is always @ref SCHEMA_VERSION.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] Result<std::string>
        serialize_checked(const Manifest &manifest, const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Reads and parses a manifest file, whole or not at all.
         * @return The @ref Manifest, a @ref parse error for corrupt contents, OutOfMemory, or one of these errors:
         *         - SizeTooLarge: the file exceeds @ref ManifestLimits::max_file_bytes at the size query, or the bytes
         *           already read overrun that cap.
         *         - FileOpenFailed: the file is missing, locked, denied, or not a regular disk file. Any other length
         *           change after the size query is also FileOpenFailed, even growth past the cap in a later read chunk.
         * @details A failed load is retryable. A caller can treat a missing file as no overrides.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] Result<Manifest>
        load(const std::filesystem::path &path, const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Writes @ref serialize_checked output to a file.
         * @return Success, a @ref serialize_checked error, SizeTooLarge above the platform single-write bound,
         *         FileOpenFailed, FileWriteFailed if the write or flush fails, or OutOfMemory in the write phase.
         * @details A @ref serialize_checked error or SizeTooLarge returns before the file opens and leaves it
         *          unchanged. The write then truncates @p path in place and is not atomic across a crash. A tear inside
         *          a heredoc, a section header, or a key line before its `=` fails the next @ref load closed. Any other
         *          tear can parse as a valid manifest with fewer keys, rungs, or records, or with a truncated value.
         *          For crash durability, atomically replace the target with a flushed temporary file.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] Result<void> save(
            const std::filesystem::path &path,
            const Manifest &manifest,
            const ManifestLimits &limits = ManifestLimits::conservative()
        );

        /**
         * @brief Merges in-code anchor defaults with optional file overrides by label. It copies each borrowed view.
         * @return The merged signatures in @p defaults order. A per-signature problem never fails the call.
         * @details The merge follows these rules:
         *          - Without a same-label override, @ref Signature::adopt adopts the default.
         *          - With one, @ref Signature::compile replaces it with the complete file record. The record inherits
         *            every in-memory-only field of the default.
         *          - An override that fails to compile, changes the declared @ref anchor::ResultDomain, or crosses
         *            between Manual and a backend kind falls back to the default.
         *          - An override whose label matches no default, or whose default is non-serializable, is ignored.
         *          - Without an accepted override, a default that @ref Signature::adopt rejects is left out. Gate a
         *            Quorum or CallArgHome default through @ref anchor::evaluate_gate.
         * @note Setup/control-plane only. Only allocation failure throws.
         */
        [[nodiscard]] Result<std::vector<Signature>>
        overlay(std::span<const anchor::Anchor> defaults, std::span<const SignatureRecord> overrides);

        /** @brief Thresholds for @ref resolve_and_gate. */
        struct GatePolicy
        {
            /// If true, safe-disable an entry whose fingerprint is @ref FingerprintState::Drifted.
            bool reject_on_fingerprint_drift = true;
            /// If true, also safe-disable an entry with no baseline (@ref FingerprintState::Unset).
            bool reject_unset_fingerprint = false;
            /** @brief Health floor in [0, 1]. If the trusted fraction falls below it, every entry is safe-disabled. */
            double min_resolved_fraction = 0.0;
            /**
             * @brief If true, safe-disable an entry that is not mutation-capable: a Manual pin or a domain mismatch.
             * @details MidHookRegister needs a code site, and VmtMethod needs a vtable. Address and PointerChain need a
             *          CodeSite or DataAddress, never a vtable or Scalar.
             */
            bool require_mutation_safe_binding = false;
            /** @brief If true, a captured image baseline of a mutation-capable entry must match the live image. */
            bool require_live_image_identity = false;
            /** @brief If true, safe-disable a mutation-capable entry that has no captured image baseline. */
            bool require_captured_image_identity = false;
            /**
             * @brief If true, a mutation-capable entry needs a winning-span content baseline that still matches.
             * @details The baseline must equal the scan witness and a guarded reread of the match span directly before
             *          publication. Unlike the image identity gates, this check sees an in-place patch of the match
             *          span under equal PE headers. For write-time certainty, use a checked mutation or install.
             */
            bool require_winning_evidence_baseline = false;
            /** @brief If true, safe-disable a mutation-capable entry unless the gate checked a contract revision. */
            bool require_contract_revision = false;

            /** @brief Rejects drift and an unset baseline. One untrusted entry safe-disables the whole manifest. */
            [[nodiscard]] static constexpr GatePolicy strict() noexcept
            {
                return GatePolicy{
                    .reject_on_fingerprint_drift = true,
                    .reject_unset_fingerprint = true,
                    .min_resolved_fraction = 1.0,
                };
            }

            /**
             * @brief @ref strict plus every mutation requirement, for a manifest that authorizes a write. It passes no
             *        mutation-capable entry unless the @ref ManifestHeader overload gets a non-zero build revision.
             */
            [[nodiscard]] static constexpr GatePolicy mutation_strict() noexcept
            {
                GatePolicy policy = strict();
                policy.require_mutation_safe_binding = true;
                policy.require_live_image_identity = true;
                policy.require_captured_image_identity = true;
                policy.require_winning_evidence_baseline = true;
                policy.require_contract_revision = true;
                return policy;
            }
        };

        /** @brief A trusted signature. Its label and binding borrow from a @ref Signature that must outlive it. */
        struct GatedSignature
        {
            /// The signature's key (a view into the source Signature).
            std::string_view label;
            /// Which anchor backend resolved it.
            anchor::AnchorKind kind = anchor::AnchorKind::Manual;
            /** @brief The resolved value as an address. Interpret it through @ref binding. */
            Address address;
            /// The consumer-facing binding (a pointer into the source Signature).
            const Binding *binding = nullptr;
        };

        /** @brief The gate that safe-disabled a signature, so a log can tell a locate failure from a refused write. */
        enum class GateReason : std::uint8_t
        {
            /// Not rejected.
            None,
            /// @ref Signature::resolve did not return a unique @ref anchor::AnchorStatus::Resolved.
            Unresolved,
            /// The declared definition changed after its baseline capture.
            FingerprintDrifted,
            /// No fingerprint baseline was captured and the policy requires one.
            FingerprintUnset,
            /// The binding cannot safely mutate the resolved typed domain, or it is a Manual pin.
            BindingCannotMutate,
            /// No contract revision was checked, or the checked revision is incompatible.
            ContractRevision,
            /// The captured image baseline is absent, or it no longer matches the live image.
            ImageIdentity,
            /// The winning-span content baseline is absent, unwitnessed, over-long, unreadable, or no longer matches.
            WinningEvidence,
            /// The whole-manifest trusted fraction fell below @ref GatePolicy::min_resolved_fraction.
            HealthFloor,
        };

        /** @brief One safe-disabled signature and why it was not trusted. */
        struct RejectedSignature
        {
            /// The signature's key (a view into the source Signature).
            std::string_view label;
            /** @brief The resolve outcome. A status other than Resolved explains a locate failure. */
            anchor::AnchorStatus status = anchor::AnchorStatus::Unresolved;
            /// The drift verdict (see @ref FingerprintState).
            FingerprintState fingerprint = FingerprintState::Unset;
            /// The specific gate that rejected this entry.
            GateReason reason = GateReason::None;
        };

        /** @brief A gated manifest: its trusted and safe-disabled signatures, plus the quality summary. */
        struct GateResult
        {
            /// Signatures that no gate rejected.
            std::vector<GatedSignature> trusted;
            /// Safe-disabled signatures, each with the @ref GateReason that rejected it.
            std::vector<RejectedSignature> rejected;
            /// The quality summary of the whole manifest, from @ref anchor::assess_quality.
            anchor::AnchorQuality quality;

            /** @brief Returns the trusted entry for @p label, or nullptr if that label was rejected or is absent. */
            [[nodiscard]] const GatedSignature *find(std::string_view label) const noexcept;
        };

        /**
         * @brief Resolves each signature and partitions the set into trusted and safe-disabled entries.
         * @param signatures The result borrows the labels and bindings of these signatures.
         * @param scope The scope for a signature that names no module.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] GateResult resolve_and_gate(
            std::span<const Signature> signatures,
            const GatePolicy &policy = {},
            Region scope = Region::host()
        );

        /**
         * @brief Like @ref resolve_and_gate, and rejects a mutation-capable entry that fails @ref revision_compatible.
         * @param build_revision The build's contract revision. 0 skips the check, as the plain overload does.
         * @note Setup/control-plane only.
         */
        [[nodiscard]] GateResult resolve_and_gate(
            std::span<const Signature> signatures,
            const ManifestHeader &header,
            std::uint32_t build_revision,
            const GatePolicy &policy = {},
            Region scope = Region::host()
        );

        /** @brief Returns the static file token that names @p kind. */
        [[nodiscard]] std::string_view binding_kind_to_string(BindingKind kind) noexcept;

        /** @brief Returns a static name for @p state. */
        [[nodiscard]] std::string_view fingerprint_state_to_string(FingerprintState state) noexcept;

        /** @brief Returns a static name for @p reason. */
        [[nodiscard]] std::string_view gate_reason_to_string(GateReason reason) noexcept;
    } // namespace manifest
} // namespace DetourModKit

#endif // DETOURMODKIT_MANIFEST_HPP
