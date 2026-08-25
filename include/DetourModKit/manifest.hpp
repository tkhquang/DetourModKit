#ifndef DETOURMODKIT_MANIFEST_HPP
#define DETOURMODKIT_MANIFEST_HPP

/**
 * @file manifest.hpp
 * @brief Signature manifest: the resolved patch-fragile contract as editable data, so a broken mod is a text edit.
 * @details SignatureRecord owns serializable anchor evidence and its consumer binding. Signature compiles candidate
 *          ladders into owned storage. @ref resolve_and_gate resolves those contracts, checks their fingerprints and
 *          quality, and safe-disables unresolved or drifted entries before a wrong register or offset can be consumed.
 * @note The file format is a separate INI parsed by the already-linked simpleini, never the settings INI. The parser
 *       and emitter live entirely in the implementation; this header names no INI type.
 * @warning `[B-100]` Never parse, compile, resolve, gate, or derive a scope under the loader lock. Pure value
 *          accessors on a compiled @ref Signature do not allocate or query the loader.
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
    // Forward-declare the one hook:: type a Binding names: a scoped enum with a fixed underlying type is complete
    // enough to declare a member, so a consumer reading only Address / PointerChain bindings need not pull the whole
    // hooking surface into every manifest TU. The full definition is reached only where the register is used.
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

        /**
         * @enum BindingKind
         * @brief How a consumer interprets what a signature located. This is the register / offset / vtable repair
         *        surface.
         * @details The @ref anchor backends locate the address and the binding says what to read there. The binding
         *          itself is inert. This module resolves the address and returns the binding, and the consumer
         *          performs the register read (@ref hook::gpr), the pointer-chain walk (@ref memory::walk with
         *          @ref memory::read), or the virtual-method hook (@ref hook::VmtHook::hook_method).
         */
        enum class BindingKind : std::uint8_t
        {
            /// The resolved value IS the address the mod wants (an inline-hook target or a resolved global).
            Address,
            /// The resolved value is a chain base: walk @ref Binding::offsets, then read value_width bytes.
            PointerChain,
            /// The resolved value is a mid-hook site; the callback reads @ref Binding::read_register via hook::gpr.
            MidHookRegister,
            /// The resolved value is a vtable base; hook the virtual slot at @ref Binding::vmt_index.
            VmtMethod
        };

        /// Sentinel for @ref Binding::xmm_index: no XMM register bound (the site reads a GPR, not a float slot).
        inline constexpr std::uint8_t XMM_INDEX_UNUSED = 0xFF;

        /**
         * @struct Binding
         * @brief The consumer-facing interpretation of a resolved signature: which register, which offset chain, which
         *        slot.
         * @details Only the fields the active @ref kind uses are meaningful. The rest keep their defaults, which is
         *          the designated-initializer discipline @ref anchor::Anchor follows.
         */
        struct Binding
        {
            /// How to interpret the resolved value.
            BindingKind kind = BindingKind::Address;
            /// PointerChain: byte offsets walked left to right from the resolved base (@ref memory::walk semantics).
            std::vector<std::ptrdiff_t> offsets;
            /// PointerChain: byte width of the leaf read at the end of the walk (e.g. 4 for a float, 8 for a pointer).
            std::uint8_t value_width = 8;
            /// MidHookRegister: the register the mid-hook callback reads (edit after a rcx -> rax drift).
            hook::Gpr read_register{};
            /// MidHookRegister: an XMM lane for a float site, or @ref XMM_INDEX_UNUSED when the value lives in a GPR.
            std::uint8_t xmm_index = XMM_INDEX_UNUSED;
            /// VmtMethod: the zero-based virtual-table slot to hook; valid values are 0 through 4095.
            std::size_t vmt_index = 0;
        };

        /**
         * @struct CandidateSpec
         * @brief One candidate-ladder rung in owning, text-editable form; compiled into a @ref scan::Candidate at load.
         * @details The serializable twin of a @ref scan::Candidate, which owns compiled Pattern bytes that no author
         *          can edit by hand. For a byte-tier rung the file carries the source AOB string and decode
         *          parameters, and @ref Signature::compile turns them back into a @ref scan::Candidate. Only the
         *          fields the active @ref mode uses are read.
         */
        struct CandidateSpec
        {
            /// Human-readable rung name, carried into the winning @ref scan::Hit for diagnostics.
            std::string name;
            /// Which resolution strategy this rung uses.
            scan::Mode mode = scan::Mode::Direct;
            /// Direct / RipRelative: the AOB DSL string, e.g. "48 8B 05 ?? ?? ?? ??".
            std::string pattern;
            /// Direct: signed byte delta added to the match (negative walks backward); 0 returns the match itself.
            std::ptrdiff_t walk_back = 0;
            /// RipRelative: byte offset from the match to the signed 4-byte displacement field.
            std::ptrdiff_t displacement_at = 0;
            /// RipRelative: total length of the referencing instruction (the next-IP base for the displacement).
            std::size_t instruction_length = 0;
            /// RttiVtable: the MSVC mangled type name, e.g. ".?AVCameraManager@@".
            std::string mangled;
            /// StringXref: the exact literal content to anchor on (no quotes).
            std::string string_text;
            /// StringXref: how the literal is stored in the image.
            scan::StringEncoding string_encoding = scan::StringEncoding::Utf8;
            /// StringXref: whether to return the referencing instruction, its enclosing function, or the pointer slot.
            scan::XrefReturn string_return = scan::XrefReturn::ReferencingInstruction;
            /// StringXref: match a trailing NUL so a prefix of a longer literal is not matched.
            bool string_require_terminator = true;
            /// StringXref: keep the lea/mov shape scan and add the broad Zydis sweep for rarer reference shapes.
            bool string_broad_match = false;
        };

        /**
         * @struct SignatureRecord
         * @brief An owning, serializable superset of @ref anchor::Anchor plus its @ref Binding: the unit an INI file
         *        round-trips.
         * @details Where @ref anchor::Anchor is a static aggregate of non-owning views authored in code, a
         *          SignatureRecord owns every string and ladder rung so it survives being read from a file and stored.
         *          Only the fields the active @ref kind uses are meaningful (the RipGlobal / CodeOperand ladder, the
         *          VtableIdentity mangled name, the StringXref facets, the ExportName module + export name, or the
         *          Manual literal); the rest keep their defaults. The two composite anchor kinds
         *          @ref anchor::AnchorKind::Quorum and
         *          @ref anchor::AnchorKind::CallArgHome are deliberately not serializable here: a Quorum composes
         *          voting members by pointer and CallArgHome has no resolver, so both stay in-code constructs gated
         *          through @ref anchor::evaluate_gate rather than the file.
         */
        struct SignatureRecord
        {
            /// Stable merge / lookup key, e.g. "player.health"; echoed into the drift report and the gate result.
            std::string label;
            /// Which anchor backend resolves this signature (one of the six serializable kinds).
            anchor::AnchorKind kind = anchor::AnchorKind::RipGlobal;
            /**
             * @brief Empty resolves within the host image (or the fallback scope); otherwise a module basename scoped
             *        through @ref Region::module_named. For ExportName this names the module whose export table holds
             *        @ref export_name.
             */
            std::string module;

            /// RipGlobal / CodeOperand: the candidate ladder resolving to the address or the instruction site.
            std::vector<CandidateSpec> ladder;

            /// VtableIdentity: the MSVC mangled type name to resolve through the reverse-RTTI walk.
            std::string mangled;

            /// CodeOperand: whether to read an immediate or a memory-operand displacement.
            scan::OperandKind operand_kind = scan::OperandKind::Immediate;
            /// CodeOperand: index into the instruction's visible operands.
            std::uint8_t operand_index = 0;
            /// CodeOperand: 0 preserves the decoded value; 1 through 8 narrows non-RIP low bytes and sign-extends.
            std::uint8_t byte_width = 0;

            /// StringXref: the exact literal content to anchor on (no quotes).
            std::string xref_text;
            /// StringXref: byte encoding of the literal in the image (Utf16le for wchar_t literals).
            scan::StringEncoding xref_encoding = scan::StringEncoding::Utf8;
            /// StringXref: whether to return the referencing instruction, its enclosing function, or the pointer slot.
            scan::XrefReturn xref_return = scan::XrefReturn::ReferencingInstruction;
            /// StringXref: match a trailing NUL so a prefix of a longer literal is not matched.
            bool xref_require_terminator = true;
            /// StringXref: keep the lea/mov shape scan and add the broad Zydis sweep for rarer reference shapes.
            bool xref_broad_match = false;

            /// Manual: the pinned literal value, taken as-is.
            std::int64_t manual_value = 0;

            /**
             * @brief Optional post-resolve validator threaded onto the compiled @ref anchor::Anchor, mirroring @ref
             *        anchor::Anchor::validator. In-memory only: a function pointer cannot round-trip through an INI
             *        file, so @ref parse never populates it and @ref serialize_checked never writes it. A consumer
             *        attaches it programmatically (after loading a manifest, or on a hand-built record) so a
             *        file-loaded or adopted signature can still assert a domain invariant instead of trusting the raw
             *        resolved address.
             */
            anchor::AnchorValidator validator = nullptr;
            /**
             * @brief Opaque pointer forwarded verbatim to @ref validator.
             * @details This field is in-memory only.
             *          The pointer is copied, but its pointee remains borrowed.
             *          The consumer must keep that pointee valid during each signature resolve.
             */
            const void *validator_context = nullptr;
            /**
             * @brief Run @ref validator on a Manual anchor too, instead of taking the pinned literal unchecked.
             * @details In-memory only.
             */
            bool validate_manual = false;
            /// Reject a backend-resolvable anchor that carries no @ref validator (fails closed). In-memory only.
            bool require_validator = false;

            /// How the consumer interprets the resolved value.
            Binding binding{};

            /**
             * @brief The @ref anchor::anchor_fingerprint captured when authored. A zero value means "not captured yet".
             * @details The fingerprint is a content hash of the signature's own declarative definition: its locate
             *          evidence (pattern bytes / mangled name / xref literal), its @ref Binding contract, and its
             *          label and module scope. It never reads the game's code. Persist it so the gate can distinguish
             *          a relocated target from a signature edit. A relocation retains the same fingerprint. A
             *          signature edit without a new baseline changes it. A value of 0 reports as "unknown", never as
             *          "drifted", so an author without a baseline is not falsely rejected.
             */
            std::uint64_t expected_fingerprint = 0;

            /**
             * @brief RipGlobal: page-protection class for byte-tier candidates. Defaults to @ref scan::Pages::Readable
             *        for backward-compatible data-global resolution; set @ref scan::Pages::Executable when every rung
             *        anchors on an instruction. Serialized as the optional `pages` key for RipGlobal records only.
             * @details Ignored by other kinds.
             */
            scan::Pages pages = scan::Pages::Readable;

            /**
             * @brief ExportName: the exact, case-sensitive export symbol name (no decoration), e.g. "Sleep". The owning
             *        module is the shared @ref module field (empty resolves the export within the fallback scope).
             * @details Serialized as the `export_name` key for ExportName records only; ignored by other kinds.
             */
            std::string export_name;

            /**
             * @brief The optional live-image baseline captured for this signature.
             * @details Serialized as `image_identity` when present. A configured identity gate rejects a captured
             *          baseline that does not match the resolved image.
             */
            scan::ImageIdentity expected_image_identity{};

            /**
             * @brief The optional winning-span content baseline captured for this signature.
             * @details Serialized as `winning_bytes`, a lowercase hex string of the captured span. This is the only
             *          baseline that sees target CONTENT: @ref expected_fingerprint hashes the record's own
             *          declaration and @ref expected_image_identity folds PE header fields, so an in-place code patch
             *          that preserves the section table moves this and neither of the others. Only a byte-signature
             *          rung can produce one.
             */
            scan::WinningEvidence expected_winning_bytes{};
        };

        /**
         * @enum FingerprintState
         * @brief The drift verdict for one signature: no baseline, the declared definition is unchanged, or it changed.
         */
        enum class FingerprintState : std::uint8_t
        {
            /// No baseline was captured (@ref SignatureRecord::expected_fingerprint is 0); drift cannot be judged.
            Unset,
            /// The live fingerprint equals the captured baseline: the signature's declared definition is unchanged.
            Match,
            /// The live fingerprint differs from the baseline (see @ref SignatureRecord::expected_fingerprint).
            Drifted
        };

        /**
         * @class Signature
         * @brief A compiled, resolvable signature: owns its candidate storage and presents an @ref anchor::Anchor view.
         * @details The bridge from the owning, serializable @ref SignatureRecord to the borrowed @ref anchor::Anchor
         *          the engine resolves. It owns the compiled ladder (a std::vector<scan::Candidate>) and the record's
         *          owned strings, and it rebuilds a borrowed @ref anchor::Anchor on demand rather than
         *          caching one, so moving a Signature can never leave a stored view dangling - the same discipline
         *          @ref scan::OwnedScanRequest::view uses. Construct one from a file record with @ref compile, or adopt
         *          an in-code anchor with @ref adopt.
         */
        class Signature
        {
        public:
            /**
             * @brief Compiles a file record into a resolvable signature, failing closed on an uncompilable rung.
             * @param record The owning record (moved in; its strings back the resolved anchor view).
             * @return The compiled Signature, or an Error: BadPattern (a ladder rung's AOB failed to compile),
             *         EmptyCandidates (a RipGlobal / CodeOperand record with no ladder), or InvalidArg (a record whose
             *         kind is the non-serializable Quorum / CallArgHome / Unset, whose kind's required evidence is
             *         empty, whose persisted policy fields (including CodeOperand byte_width) are out of range, whose
             *         label or string fields could not round-trip through the file grammar, or whose binding carries a
             *         non-default value in a field its @ref BindingKind never reads).
             * @note Setup/control-plane only: compiling a ladder parses each rung's Pattern.
             */
            [[nodiscard]] static Result<Signature> compile(SignatureRecord record);

            /**
             * @brief Adopts an in-code @ref anchor::Anchor and owns its evidence.
             * @param source The in-code anchor.
             *        The function copies its borrowed views.
             * @return The owning Signature, or an Error: InvalidArg (a Quorum, CallArgHome, or Unset anchor, a
             *         serializable anchor whose required evidence is empty, an out-of-range persisted policy field
             *         (including CodeOperand byte_width), or a label or string field that could not round-trip through
             *         the file grammar).
             * @details The counterpart to @ref compile for a signature that originates in code rather than a file. It
             *          copies the anchor's borrowed site candidates and strings into this object so the adopted
             *          signature outlives the caller's anchor table. The resulting record carries no ladder text (a
             *          compiled Pattern cannot be turned back into its source AOB), so @ref serialize_checked of an
             *          adopted signature's record omits its ladder; capture a fresh record from the file side to
             *          serialize it.
             * @note Setup/control-plane only: the adoption copies the anchor's evidence into owned storage.
             */
            [[nodiscard]] static Result<Signature> adopt(const anchor::Anchor &source);

            /**
             * @brief Resolves this signature to a value through its anchor backend, fail-closed.
             * @param fallback_scope The module image to resolve within when the record names no module; defaults to the
             *                       host executable. A record that names a module always resolves within that module,
             *                       ignoring this argument.
             * @return A @ref anchor::ResolvedAnchor carrying the outcome and (on success) the value.
             * @note Setup/control-plane only (see @ref anchor::resolve).
             */
            [[nodiscard]] anchor::ResolvedAnchor resolve(Region fallback_scope = Region::host()) const;

            /**
             * @brief The effective scope this signature resolves within.
             * @return @ref Region::module_named for the record's module, or @ref Region::host when it names none.
             * @note Setup/control-plane only: queries the loader.
             */
            [[nodiscard]] Region scope() const noexcept;

            /**
             * @brief The live fingerprint of this signature, recomputed from its current declarative inputs.
             * @return A content hash over the signature's declared definition: the @ref anchor::anchor_fingerprint of
             *         the locate evidence (compiled ladder, mangled name, xref literal) combined with the @ref Binding
             *         contract (register / offset chain / value width / vtable slot), the record label, and the module
             *         scope @ref resolve walks.
             * @details Content-derived and address-independent: it reads no game memory, so it is stable across runs
             *          and rebuilds on one platform and changes exactly when the signature's declared definition
             *          changes - a re-authored pattern, a renamed type, a different literal, or an edited binding.
             */
            [[nodiscard]] std::uint64_t current_fingerprint() const noexcept;

            /**
             * @brief Compares the live fingerprint to the captured baseline.
             * @return @ref FingerprintState::Unset when no baseline was captured, @ref FingerprintState::Match when the
             *         declared definition is unchanged, else @ref FingerprintState::Drifted.
             */
            [[nodiscard]] FingerprintState fingerprint_state() const noexcept;

            /**
             * @brief Adopts the live fingerprint as the new baseline, after a verified repair.
             * @details Call this once a hand edit (new pattern, moved register, shifted offset) has been confirmed
             *          correct, so the gate trusts the repaired signature again on the next run. Persist the updated
             *          @ref record afterward to make the recapture durable.
             * @note Setup/control-plane only: the recapture mutates the trust baseline.
             */
            void recapture_fingerprint() noexcept;

            /**
             * @brief Re-resolves this signature and adopts the live fingerprint, image identity, and winning-span
             *        content as the new baselines.
             * @param fallback_scope The default module image for a signature that names no module; must be the same
             *                       scope the consumer will gate under, since a baseline captured in one scope does not
             *                       describe another.
             * @return Nothing on success, or an Error explaining why no baseline was adopted.
             * @details The recapture @ref GatePolicy::mutation_strict needs: it is the only operation that fills
             *          @ref SignatureRecord::expected_image_identity and
             *          @ref SignatureRecord::expected_winning_bytes from live evidence.
             *
             *          Atomic: every baseline is computed before any is stored, so a failure leaves all three at their
             *          previous values rather than a half-updated mixture that would gate on one game version's
             *          content and another's identity. Fails with @ref ErrorCode::NoMatch when the signature does not
             *          resolve, and with @ref ErrorCode::UnexpectedShape when the resolved rung witnesses no owning
             *          image or no usable content span - an RTTI, export, string-xref, or Manual kind, or evidence
             *          longer than @ref scan::MAX_MUTATION_WITNESS_BYTES. Persist @ref record afterward to make it
             *          durable.
             * @note Setup/control-plane only: re-resolving walks the signature's scope.
             */
            [[nodiscard]] Result<void> recapture(Region fallback_scope = Region::host());

            /// The signature's stable key.
            [[nodiscard]] std::string_view label() const noexcept;
            /// Which anchor backend resolves this signature.
            [[nodiscard]] anchor::AnchorKind kind() const noexcept;
            /// The consumer-facing binding (register / offsets / vtable slot).
            [[nodiscard]] const Binding &binding() const noexcept;
            /// The owning record backing this signature (for @ref serialize_checked after @ref recapture_fingerprint).
            [[nodiscard]] const SignatureRecord &record() const noexcept;

        private:
            friend class detail::GateAccess;

            // The two factories are the only construction path: compile() parses a record's ladder text into m_ladder,
            // adopt() copies an anchor's site into m_ladder, and both keep the owning record so make_anchor() can view
            // its strings. The compiled ladder is stored separately from the record's text ladder because the resolver
            // needs scan::Candidate objects, which are not what the file round-trips.
            Signature(SignatureRecord record, std::vector<scan::Candidate> ladder) noexcept;

            // Builds a borrowed anchor::Anchor viewing this object's owned storage. Rebuilt on demand (never cached) so
            // no view outlives a move of *this; the returned Anchor is valid only for the duration of the call it
            // feeds.
            [[nodiscard]] anchor::Anchor make_anchor() const noexcept;

            // Resolves through the private provenance path and returns the selected match span for the mutation gate.
            [[nodiscard]] anchor::ResolvedAnchor resolve_for_gate(Region fallback_scope, Region &winning_span) const;

            SignatureRecord m_record;
            std::vector<scan::Candidate> m_ladder;
        };

        /// The manifest INI format version this build reads and writes. Bumped only on an incompatible format change.
        inline constexpr std::uint32_t SCHEMA_VERSION = 1;

        /**
         * @struct ManifestHeader
         * @brief The `[manifest]` metadata: the DetourModKit parse-format schema and the author's contract revision.
         * @details Two independent version axes. @ref schema is the file-format version, which states whether this
         *          build can parse the file at all. @ref parse rejects a schema it does not understand. @ref revision
         *          is the mod author's own signature-contract epoch, bumped only when an in-code change makes older
         *          manifests incompatible (a renamed label, a re-meaning of a binding, a dropped signature).
         *          DetourModKit never interprets @ref revision; a consumer compares it to its build's expected value
         *          through @ref revision_compatible and safe-ignores a stale file. This catches staleness the
         *          per-signature fingerprint gate cannot, such as a renamed label or a changed meaning for an existing
         *          binding.
         */
        struct ManifestHeader
        {
            /// The format version the file declares; @ref parse rejects a value this build cannot read.
            std::uint32_t schema = SCHEMA_VERSION;
            /// The author's signature-contract epoch (0 = unversioned); compared to a build revision, never by DMK.
            std::uint32_t revision = 0;
        };

        /**
         * @struct Manifest
         * @brief A parsed manifest: its @ref ManifestHeader plus the signature records in file order.
         */
        struct Manifest
        {
            /// The `[manifest]` metadata (schema and contract revision).
            ManifestHeader header{};
            /// The signatures, one per `[sig.<label>]` section, in file order.
            std::vector<SignatureRecord> records{};
        };

        /**
         * @struct ManifestLimits
         * @brief The resource caps the manifest parser and checked persistence functions enforce.
         * @details A default-constructed value is @ref conservative(). Trusted authoring tools may opt into
         *          @ref advanced(); untrusted files must use bounded limits. A violation returns
         *          @ref ErrorCode::SizeTooLarge without publishing a partial result.
         */
        struct ManifestLimits
        {
            /// Largest accepted encoded text size in bytes.
            std::size_t max_file_bytes{1u << 20};
            /// Largest accepted number of INI sections (header, records, and rung sub-sections combined).
            std::size_t max_sections{1u << 15};
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

            /**
             * @brief Raises every numeric cap to its maximum while retaining grammar and semantic validation.
             * @return Limits intended only for a trusted authoring tool, never for an untrusted file.
             */
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
         * @brief Reports whether a manifest may be applied under a build's signature-contract revision.
         * @param header The parsed manifest header.
         * @param build_revision The revision this build authored its in-code signatures against; 0 disables the check.
         * @return true when @p build_revision is 0 (the consumer opts out of revision gating) or the manifest's
         *         @ref ManifestHeader::revision equals it; false when the file targets a different contract epoch.
         * @details Bump @p build_revision (and the file's `revision`) only on an incompatible contract change (see
         *          @ref ManifestHeader). On a false result a consumer logs and falls back to its in-code defaults.
         */
        [[nodiscard]] bool revision_compatible(const ManifestHeader &header, std::uint32_t build_revision) noexcept;

        /**
         * @brief Parses a manifest's INI text.
         * @param text The manifest text (a `[manifest]` header plus one `[sig.<label>]` section per contract).
         * @param limits The resource caps to enforce; the default is @ref ManifestLimits::conservative().
         * @return The parsed @ref Manifest (header plus records in file order), or an Error: MissingHeader (no
         *         `[manifest]` section or an unsupported schema), MalformedLine (a line, field, or enum token that
         *         does not parse, a non-canonical section or key spelling, or a key that is inert for its record's
         *         declared binding kind or its rung's mode), ManifestIdentityCollision (a case-, whitespace-, or
         *         exactly-duplicated section, or a whitespace-variant or exactly-duplicated key, but a miscased key is
         *         MalformedLine before collision detection), ManifestFramingUnsafe (an unterminated `<<<` heredoc
         *         value, an opener with an empty tag, or a heredoc whose first body line is its terminator),
         *         SizeTooLarge (encoded text, a section, key, field, record, rung, or aggregate exceeding @p limits),
         *         or OutOfMemory (an allocation failed).
         * @details Fails closed: a manifest that cannot be trusted to describe the signatures faithfully is rejected
         *          whole, never partially applied. A raw prepass rejects every identity collision before the
         *          case-sensitive backend reads the text, so no merged or swallowed record can masquerade as another.
         *          A missing optional key falls back to its default, so an absent `revision` is 0. A key that is
         *          present must parse, so a blank enum, numeric, or boolean value is MalformedLine instead of a
         *          default. A blank string-valued key reads as empty.
         * @note Setup/control-plane only: parses and allocates bounded manifest state.
         */
        [[nodiscard]] Result<Manifest>
        parse(std::string_view text, const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Serializes a manifest to INI text, rejecting anything that could not round-trip.
         * @param manifest The header (its @ref ManifestHeader::revision is emitted when non-zero) and records to emit.
         * @param limits The resource caps to enforce; the default is @ref ManifestLimits::conservative().
         * @return The manifest text, round-trippable through @ref parse, or an Error: InvalidArg (a record whose label
         *         or a string field cannot be framed, an out-of-range persisted policy field (including CodeOperand
         *         byte_width), or a binding carrying a non-default inert field), ManifestIdentityCollision (two records
         *         whose labels fold to one section, or a record whose label folds into another record's rung section),
         *         SizeTooLarge (encoded text, a record, rung, field, or aggregate exceeding @p limits), or OutOfMemory.
         *         The `schema` line always reflects this build's @ref SCHEMA_VERSION.
         * @details The single encoder: @ref save routes through it, so a value that a later @ref parse could not read
         *          back is refused at write time rather than persisted. A rejection is a typed error, never an empty or
         *          truncated string.
         * @note Setup/control-plane only: validates and allocates bounded manifest text.
         */
        [[nodiscard]] Result<std::string>
        serialize_checked(const Manifest &manifest, const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Reads and parses a manifest file.
         * @param path Source file path.
         * @param limits The resource caps to enforce; the default is @ref ManifestLimits::conservative().
         * @return The parsed @ref Manifest, or FileOpenFailed (missing, locked, denied, or not a regular disk file), a
         *         parse error (MissingHeader / MalformedLine / ManifestIdentityCollision / ManifestFramingUnsafe) when
         *         the file is present but its contents are corrupt, SizeTooLarge (the file exceeds
         *         @ref ManifestLimits::max_file_bytes at the size query, or the bytes already read overrun the cap), or
         *         OutOfMemory. Any other length change detected after the size query fails as FileOpenFailed, including
         *         growth whose cap overrun would only land in a later read chunk.
         * @details The read is materialized whole into a bounded buffer or not at all: a non-disk special file, an
         *          oversize file, a file a writer extends after the size query, and an allocation failure each return a
         *          typed error and touch no previously loaded manifest, so the caller's trusted generation survives a
         *          failed reload and the same input is retryable.
         * @note A missing file is a distinct, recoverable FileOpenFailed, so an overlay can treat "no file" as "no
         *       overrides" (the defaults pass through) rather than a hard failure.
         * @note Setup/control-plane only: performs bounded file I/O and parsing.
         */
        [[nodiscard]] Result<Manifest>
        load(const std::filesystem::path &path, const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Writes a manifest to a file via @ref serialize_checked.
         * @param path Destination file path.
         * @param manifest The manifest to serialize.
         * @param limits The resource caps to enforce; the default is @ref ManifestLimits::conservative().
         * @return Empty on success, or an Error: any @ref serialize_checked rejection (the manifest could not be
         *         encoded to a round-trippable form), SizeTooLarge when the encoded text exceeds the platform's
         *         single-write bound, FileOpenFailed when the file could not be opened for writing, FileWriteFailed
         *         when the stream failed during the write or flush, or OutOfMemory when the write phase itself fails
         *         to allocate.
         * @details The encode is validated before the file is opened, so a manifest that cannot round-trip never
         *          reaches disk. The write truncates @p path in place and is not atomic across a crash. A tear
         *          inside a line or heredoc fails the next @ref load closed, so the in-code defaults stay in effect.
         *          A tear at a record boundary parses as a valid shorter manifest. For a crash-durable replacement,
         *          stage @ref serialize_checked output through a temporary file, flush it to disk, and replace the
         *          target with the platform's atomic replace.
         * @note Setup/control-plane only: performs bounded serialization and file I/O.
         */
        [[nodiscard]] Result<void> save(
            const std::filesystem::path &path,
            const Manifest &manifest,
            const ManifestLimits &limits = ManifestLimits::conservative()
        );

        /**
         * @brief Merges in-code anchor defaults with optional file overrides.
         * @param defaults The in-code anchors.
         *        The function copies each borrowed view.
         * @param overrides The file records from @ref load.
         *        An empty span passes the defaults through untouched.
         * @return The merged, compiled signatures in @p defaults order. A per-signature problem never fails the whole
         *         overlay (fail-soft); the Result carries a failure only if a future merge-wide error mode is added.
         * @note Setup/control-plane only, and not noexcept: like the resolvers it drives, its sole throwing path is
         *       allocation failure. A bad file entry does not throw or fail; it falls back to the in-code default.
         * @details The adoption model in one call, fail-soft like @ref config::bind.
         *          - A default with no same-label override is adopted as-is (@ref Signature::adopt).
         *          - A default with a same-label override is replaced by the file (@ref Signature::compile), so a
         *            game update that broke two of twenty signatures needs only those two file entries.
         *          - A malformed override falls back to the in-code default, so an override never makes the result
         *            worse than a missing file.
         *          - An override whose label matches no default is inert and is not included.
         *          An accepted override supplies the complete serializable record.
         *          The effective override inherits these code-owned fields:
         *          - @ref SignatureRecord::validator
         *          - @ref SignatureRecord::validator_context
         *          - @ref SignatureRecord::validate_manual
         *          - @ref SignatureRecord::require_validator
         *          These contract changes fall back to the default:
         *          - An override that changes the default's declared @ref anchor::ResultDomain falls back to the
         *            default.
         *          - An override that crosses between Manual and a backend kind falls back to the default.
         *          An override for a non-serializable default is ignored.
         *          A flat file rung cannot preserve a quorum's corroboration.
         *          A default with a non-serializable kind or empty required evidence cannot be adopted.
         *          Callers use @ref anchor::evaluate_gate for non-serializable anchors.
         */
        [[nodiscard]] Result<std::vector<Signature>>
        overlay(std::span<const anchor::Anchor> defaults, std::span<const SignatureRecord> overrides);

        /**
         * @struct GatePolicy
         * @brief The trust thresholds @ref resolve_and_gate applies. Defaults reject drift but tolerate an unset
         *        baseline.
         */
        struct GatePolicy
        {
            /**
             * @brief When true (the default), a signature whose fingerprint no longer matches its captured baseline
             *        (see @ref SignatureRecord::expected_fingerprint) is safe-disabled.
             */
            bool reject_on_fingerprint_drift = true;
            /**
             * @brief When true, a signature with no captured baseline (@ref FingerprintState::Unset) is also
             *        safe-disabled. The default false treats "unknown" as trusted, so an author who has not captured
             *        fingerprints yet is not blocked.
             */
            bool reject_unset_fingerprint = false;
            /**
             * @brief Optional whole-manifest health floor in [0, 1]: if the fraction of trusted signatures falls below
             *        it, every signature is rejected. The default 0 imposes no floor (each signature stands alone).
             */
            double min_resolved_fraction = 0.0;
            /**
             * @brief When true, a resolved signature is trusted to AUTHORIZE A WRITE only when its binding can safely
             *        mutate the resolved typed domain: a Manual pin (no live evidence, cannot self-heal) authorizes no
             *        mutation, and the binding kind must match the resolved domain - a MidHook needs a code site, a
             *        VmtMethod a vtable, and an Address / pointer chain a CodeSite or DataAddress, never a vtable or
             *        Scalar. The default false leaves a read-only manifest free to carry a Manual or value-only
             *        binding.
             */
            bool require_mutation_safe_binding = false;
            /**
             * @brief When true, a captured image baseline must match the live image for a mutation-capable entry.
             * @details An absent baseline leaves the entry image-agnostic. Manual values are unaffected. Pair with
             *          @ref require_captured_image_identity to make the baseline mandatory rather than optional.
             */
            bool require_live_image_identity = false;
            /**
             * @brief When true, a mutation-capable entry with no captured image baseline is safe-disabled.
             * @details Closes the read-only default's tolerance of an absent baseline.
             */
            bool require_captured_image_identity = false;
            /**
             * @brief When true, a mutation-capable entry must carry a winning-span content baseline that still matches.
             * @details This gate compares target content. It first compares the baseline with the scan witness.
             *          Directly before trust publication, it reads the selected match span through the guarded memory
             *          primitive. It compares every byte again. An absent baseline, an absent span, an over-long span,
             *          a read fault, or any byte difference rejects the entry. This check catches an equal-layout
             *          in-place code patch, which @ref require_live_image_identity cannot see. It checks freshness
             *          directly before gate publication, not at a later consumer write. A consumer that requires
             *          write-time certainty must use a checked mutation or install operation.
             */
            bool require_winning_evidence_baseline = false;
            /**
             * @brief When true, a mutation-capable entry is safe-disabled unless a contract revision was actually
             *        checked.
             * @details The plain @ref resolve_and_gate overload runs no revision check at all, and the header-threaded
             *          overload skips it when @c build_revision is 0. Either path would otherwise authorize a write
             *          against a manifest whose author contract was never compared.
             */
            bool require_contract_revision = false;

            /**
             * @brief The strictest gate. Reject drift and an unset baseline, and require every signature to resolve.
             * @details Inverts the lenient default: an unset baseline is treated as untrusted. The manifest passes
             *          only when the ENTIRE set is trusted (min_resolved_fraction 1.0). A single drifted or unresolved
             *          feature therefore safe-disables the whole manifest.
             * @return A GatePolicy with reject_on_fingerprint_drift and reject_unset_fingerprint both true and
             *         min_resolved_fraction 1.0.
             */
            [[nodiscard]] static constexpr GatePolicy strict() noexcept
            {
                return GatePolicy{
                    .reject_on_fingerprint_drift = true,
                    .reject_unset_fingerprint = true,
                    .min_resolved_fraction = 1.0,
                };
            }

            /**
             * @brief The strict gate PLUS every mutation-authorization requirement, for a manifest that drives a patch.
             * @details A mutation-capable entry needs a captured fingerprint and a captured live image identity that
             *          matches. It also needs resolve evidence that matches its baseline and a fresh guarded read. The
             *          entry needs a mutation-safe typed binding that is not a Manual and a checked contract revision.
             *          The revision check requires the @ref ManifestHeader overload with a nonzero build revision.
             *          Read-only lookup is unaffected. The plain overload, a zero build revision, and an uncaptured
             *          baseline all remain usable for resolution. They cannot authorize a write.
             * @return A strict policy with every mutation requirement armed.
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

        /**
         * @struct GatedSignature
         * @brief One trusted signature: its resolved address paired with the binding that says how to read it.
         * @details @ref label and @ref binding are views into the source @ref Signature, so a GateResult is valid only
         *          while the signatures it gated stay alive.
         */
        struct GatedSignature
        {
            /// The signature's key (a view into the source Signature).
            std::string_view label;
            /// Which anchor backend resolved it.
            anchor::AnchorKind kind = anchor::AnchorKind::Manual;
            /// The resolved value as an address; interpret it per @ref binding.
            Address address;
            /// The consumer-facing binding (a pointer into the source Signature).
            const Binding *binding = nullptr;
        };

        /**
         * @enum GateReason
         * @brief Which gate safe-disabled a signature, so a log can tell a locate failure from a refused write
         *        authorization.
         */
        enum class GateReason : std::uint8_t
        {
            /// Not rejected.
            None,
            /// @ref Signature::resolve did not return a unique @ref anchor::AnchorStatus::Resolved.
            Unresolved,
            /// The declared definition was edited without re-capturing its baseline.
            FingerprintDrifted,
            /// No fingerprint baseline was captured and the policy requires one.
            FingerprintUnset,
            /// The binding cannot safely mutate the resolved typed domain, or it is a Manual pin.
            BindingCannotMutate,
            /// No contract revision was checked, or the checked revision is incompatible.
            ContractRevision,
            /// The captured image baseline is absent, or it no longer matches the live image.
            ImageIdentity,
            /// The winning-span content baseline is absent, unwitnessed, over-long, or no longer matches.
            WinningEvidence,
            /// The whole-manifest trusted fraction fell below @ref GatePolicy::min_resolved_fraction.
            HealthFloor,
        };

        /**
         * @struct RejectedSignature
         * @brief One safe-disabled signature and why it was not trusted.
         */
        struct RejectedSignature
        {
            /// The signature's key (a view into the source Signature).
            std::string_view label;
            /// The resolve outcome; a non-Resolved status is why locate failed, if it did.
            anchor::AnchorStatus status = anchor::AnchorStatus::Unresolved;
            /// The drift verdict (see @ref FingerprintState).
            FingerprintState fingerprint = FingerprintState::Unset;
            /// The specific gate that rejected this entry.
            GateReason reason = GateReason::None;
        };

        /**
         * @struct GateResult
         * @brief The partition of a gated manifest into trusted and safe-disabled, plus the health summary.
         */
        struct GateResult
        {
            /// Signatures healthy enough to act on.
            std::vector<GatedSignature> trusted;
            /// Signatures safe-disabled because they failed to resolve, drifted, or fell under the health floor.
            std::vector<RejectedSignature> rejected;
            /// The robustness summary of the whole manifest, from @ref anchor::assess_quality.
            anchor::AnchorQuality quality;

            /**
             * @brief Looks up a trusted signature by label.
             * @param label The signature key.
             * @return The trusted entry, or nullptr when no trusted signature carries that label (it was rejected or
             *         never present). A consumer that safe-disables a feature then finds nothing and does not act.
             */
            [[nodiscard]] const GatedSignature *find(std::string_view label) const noexcept;
        };

        /**
         * @brief Resolves a manifest and partitions it into trusted vs safe-disabled signatures.
         * @param signatures The compiled signatures (from @ref overlay or @ref Signature::compile). Kept alive by the
         *                   caller; the result borrows their labels and bindings.
         * @param policy The trust thresholds.
         * @param scope The default module image for signatures that name no module; defaults to the host executable.
         * @return The partition plus the manifest health summary.
         * @details A signature is rejected when its @ref Signature::resolve does not return a unique
         *          @ref anchor::AnchorStatus::Resolved, when its fingerprint drifted under
         *          @ref GatePolicy::reject_on_fingerprint_drift or is unset under
         *          @ref GatePolicy::reject_unset_fingerprint, when a configured mutation-authorization gate under
         *          @ref GatePolicy rejects its cleanly resolved entry, or when the whole-manifest trusted fraction
         *          falls below @ref GatePolicy::min_resolved_fraction. The entry's @ref GateReason names the gate
         *          that rejected it. A rejected feature installs no hook and reads no pointer. It stays off.
         * @note Setup/control-plane only: resolving a manifest walks each signature's scope.
         */
        [[nodiscard]] GateResult resolve_and_gate(
            std::span<const Signature> signatures,
            const GatePolicy &policy = {},
            Region scope = Region::host()
        );

        /**
         * @brief Resolves and gates a manifest under a mandatory build-revision check for mutation-capable entries.
         * @param signatures The compiled signatures (from @ref overlay or @ref Signature::compile), kept alive by the
         *                   caller.
         * @param header The parsed @ref ManifestHeader carrying the file's author-contract
         *               @ref ManifestHeader::revision.
         * @param build_revision The revision this build authored its in-code signatures against; 0 opts out of
         *                       @ref revision_compatible, leaving this overload equivalent to the plain
         *                       @ref resolve_and_gate.
         * @param policy The trust thresholds; compose @ref GatePolicy::mutation_strict for a manifest that drives a
         *               write.
         * @param scope The default module image for signatures that name no module.
         * @return The partition plus the manifest health summary.
         * @details A non-zero incompatible revision rejects mutation-capable entries even when they resolve. Manual
         *          values remain available.
         * @note Setup/control-plane only: resolving a manifest walks each signature's scope.
         */
        [[nodiscard]] GateResult resolve_and_gate(
            std::span<const Signature> signatures,
            const ManifestHeader &header,
            std::uint32_t build_revision,
            const GatePolicy &policy = {},
            Region scope = Region::host()
        );

        /**
         * @brief Maps a @ref BindingKind to a short human-readable label (its file token).
         * @param kind The binding kind.
         * @return A static string view naming the kind.
         */
        [[nodiscard]] std::string_view binding_kind_to_string(BindingKind kind) noexcept;

        /**
         * @brief Maps a @ref FingerprintState to a short human-readable label.
         * @param state The fingerprint state.
         * @return A static string view naming the state.
         */
        [[nodiscard]] std::string_view fingerprint_state_to_string(FingerprintState state) noexcept;

        /**
         * @brief Maps a @ref GateReason to a short human-readable label.
         * @param reason The rejection reason.
         * @return A static string view naming the reason.
         */
        [[nodiscard]] std::string_view gate_reason_to_string(GateReason reason) noexcept;
    } // namespace manifest
} // namespace DetourModKit

#endif // DETOURMODKIT_MANIFEST_HPP
