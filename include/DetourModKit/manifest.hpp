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
        /**
         * @enum BindingKind
         * @brief How a consumer interprets what a signature located. This is the register / offset / vtable repair
         *        surface.
         * @details The @ref anchor backends answer "where is it"; the binding answers "what do I read there, and how".
         *          Both halves are data, so a register churn or a field move is a file edit, not a recompile. The
         *          binding itself is inert: this module resolves the address and hands back the binding; the consumer
         *          performs the register read (@ref hook::gpr), the pointer-chain walk (@ref memory::walk +
         *          @ref memory::read), or the virtual-method hook (@ref hook::VmtHook::hook_method) with it.
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
         * @details Only the fields the active @ref kind uses are meaningful; the rest keep their defaults, exactly the
         *          designated-initializer discipline @ref anchor::Anchor follows. Bundling the binding with the locate
         *          half keeps one editable unit per feature: "this signature locates the fov write, and its value lives
         *          in this register" is one section in the file.
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
         * @details The serializable twin of a @ref scan::Candidate. A @ref scan::Candidate owns compiled Pattern bytes
         *          that cannot be edited by hand, so the file carries the source AOB string and decode parameters here
         *          and @ref Signature::compile turns them back into a @ref scan::Candidate. Only the fields the active
         *          @ref mode uses are read.
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
            /// CodeOperand: 0 returns the decoded width; > 0 narrows to this many bytes then re-sign-extends.
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
            /// Opaque pointer forwarded verbatim to @ref validator. In-memory only (see @ref validator).
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
             * @brief The @ref anchor::anchor_fingerprint captured at authoring time; 0 means "not captured yet".
             * @details The fingerprint is a content hash of the signature's own declarative definition -- its locate
             *          evidence (pattern bytes / mangled name / xref literal), its @ref Binding contract, and its
             *          label and module scope -- and it never reads the game's code. Persisting it alongside the
             *          signature is what lets the gate tell a target that merely relocated (same declaration, the
             *          fingerprint still matches, so the self-heal
             *          is trusted) apart from a signature whose definition was edited without re-capturing the baseline
             *          (the fingerprint differs, so the edit is unverified and its binding cannot be trusted). A value
             *          of 0 reports as "unknown", never as "drifted", so an author who has not captured a baseline is
             *          not falsely rejected.
             */
            std::uint64_t expected_fingerprint = 0;

            /**
             * @brief RipGlobal: page-protection class for byte-tier candidates. Defaults to @ref scan::Pages::Readable
             *        for backward-compatible data-global resolution; set @ref scan::Pages::Executable when every rung
             *        anchors on an instruction. Serialized as the optional `pages` key for RipGlobal records only.
             * @details Ignored by other kinds. Appended to preserve positional aggregate initialization of the
             *          established record fields.
             */
            scan::Pages pages = scan::Pages::Readable;

            /**
             * @brief ExportName: the exact, case-sensitive export symbol name (no decoration), e.g. "Sleep". The owning
             *        module is the shared @ref module field (empty resolves the export within the fallback scope).
             * @details Serialized as the `export_name` key for ExportName records only; ignored by other kinds.
             *          Appended to preserve positional aggregate initialization of the established record fields.
             */
            std::string export_name;
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
            /**
             * @brief The live fingerprint differs from the baseline: the definition was edited without re-capturing, so
             *        the edit is unverified and must not be trusted.
             */
            Drifted
        };

        /**
         * @class Signature
         * @brief A compiled, resolvable signature: owns its candidate storage and presents an @ref anchor::Anchor view.
         * @details The bridge from the owning, serializable @ref SignatureRecord to the borrowed @ref anchor::Anchor
         *          the engine resolves. It owns the compiled ladder (a std::vector<scan::Candidate>) and the record's
         *          owned strings, and it rebuilds a borrowed @ref anchor::Anchor on demand rather than
         *          caching one, so moving a Signature can never leave a stored view dangling -- the same discipline
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
             *         empty, whose persisted enums are out of range, whose label or string fields could not round-trip
             *         through the file grammar, or whose binding carries a non-default value in a field its
             *         @ref BindingKind never reads).
             * @note Setup/control-plane only: compiling a ladder parses each rung's Pattern.
             */
            [[nodiscard]] static Result<Signature> compile(SignatureRecord record);

            /**
             * @brief Adopts an in-code @ref anchor::Anchor as a signature, deep-copying its evidence into owned
             *          storage.
             * @param source The in-code anchor (one of the six serializable kinds); its views are copied, not
             *        retained.
             * @return The owning Signature, or an Error: InvalidArg (a Quorum, CallArgHome, or Unset anchor, a
             *         serializable anchor whose required evidence is empty, an out-of-range persisted enum, or a label
             *         or string field that could not round-trip through the file grammar).
             * @details The counterpart to @ref compile for a signature that originates in code rather than a file. It
             *          copies the anchor's borrowed site candidates and strings into this object so the adopted
             *          signature outlives the caller's anchor table. The resulting record carries no ladder text (a
             *          compiled Pattern cannot be turned back into its source AOB), so @ref serialize_checked of an
             *          adopted signature's record omits its ladder; capture a fresh record from the file side to
             *          serialize it.
             */
            [[nodiscard]] static Result<Signature> adopt(const anchor::Anchor &source);

            /**
             * @brief Resolves this signature to a value through its anchor backend, fail-closed.
             * @param fallback_scope The module image to resolve within when the record names no module; defaults to the
             *                       host executable. A record that names a module always resolves within that module,
             *                       ignoring this argument.
             * @return A @ref anchor::ResolvedAnchor carrying the outcome and (on success) the value.
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
             *          changes -- a re-authored pattern, a renamed type, a different literal, or an edited binding.
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
             */
            void recapture_fingerprint() noexcept;

            /// The signature's stable key.
            [[nodiscard]] std::string_view label() const noexcept;
            /// Which anchor backend resolves this signature.
            [[nodiscard]] anchor::AnchorKind kind() const noexcept;
            /// The consumer-facing binding (register / offsets / vtable slot).
            [[nodiscard]] const Binding &binding() const noexcept;
            /// The owning record backing this signature (for @ref serialize_checked after @ref recapture_fingerprint).
            [[nodiscard]] const SignatureRecord &record() const noexcept;

        private:
            // The two factories are the only construction path: compile() parses a record's ladder text into m_ladder,
            // adopt() copies an anchor's site into m_ladder, and both keep the owning record so make_anchor() can view
            // its strings. The compiled ladder is stored separately from the record's text ladder because the resolver
            // needs scan::Candidate objects, which are not what the file round-trips.
            Signature(SignatureRecord record, std::vector<scan::Candidate> ladder) noexcept;

            // Builds a borrowed anchor::Anchor viewing this object's owned storage. Rebuilt on demand (never cached) so
            // no view outlives a move of *this; the returned Anchor is valid only for the duration of the call it
            // feeds.
            [[nodiscard]] anchor::Anchor make_anchor() const noexcept;

            SignatureRecord m_record;
            std::vector<scan::Candidate> m_ladder;
        };

        /// The manifest INI format version this build reads and writes. Bumped only on an incompatible format change.
        inline constexpr std::uint32_t SCHEMA_VERSION = 1;

        /**
         * @struct ManifestHeader
         * @brief The `[manifest]` metadata: the DetourModKit parse-format schema and the author's contract revision.
         * @details Two independent version axes. @ref schema is the file-format version -- whether this build can parse
         *          the file at all; @ref parse rejects a schema it does not understand. @ref revision is the mod
         *          author's own signature-contract epoch, bumped only when an in-code change makes older manifests
         *          incompatible (a renamed label, a re-meaning of a binding, a dropped signature). DetourModKit never
         *          interprets @ref revision; a consumer compares it to its build's expected value through
         *          @ref revision_compatible and safe-ignores a stale file. This catches staleness the per-signature
         *          fingerprint gate cannot, such as a renamed label or a changed meaning for an existing binding.
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
                return ManifestLimits{.max_file_bytes = MAX_VALUE,
                                      .max_sections = MAX_VALUE,
                                      .max_keys_per_section = MAX_VALUE,
                                      .max_records = MAX_VALUE,
                                      .max_rungs_per_record = MAX_VALUE,
                                      .max_field_bytes = MAX_VALUE,
                                      .max_total_decoded_bytes = MAX_VALUE};
            }
        };

        /**
         * @brief Reports whether a manifest may be applied under a build's signature-contract revision.
         * @param header The parsed manifest header.
         * @param build_revision The revision this build authored its in-code signatures against; 0 disables the check.
         * @return true when @p build_revision is 0 (the consumer opts out of revision gating) or the manifest's
         *         @ref ManifestHeader::revision equals it; false when the file targets a different contract epoch.
         * @details The manifest-level counterpart to the per-signature fingerprint gate. Bump @p build_revision (and
         *          the file's `revision`) only on a breaking in-code contract change, so a routine mod update leaves
         *          still-valid repair files working and only a genuinely incompatible file is rejected. On a false
         *          result a consumer logs and falls back to its in-code defaults (an empty override set), telling the
         *          user to delete the stale file or, only after re-verifying it, bump its `revision`.
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
         *         exactly-duplicated section, or a whitespace-variant or exactly-duplicated key -- a miscased key is
         *         MalformedLine before collision detection), ManifestFramingUnsafe (an unterminated `<<<` heredoc
         *         value, an opener with an empty tag, or a heredoc whose first body line is its terminator),
         *         SizeTooLarge (encoded text, a section, key, field, record, rung, or aggregate exceeding @p limits),
         *         or OutOfMemory (an allocation failed).
         * @details Fails closed, mirroring @ref rtti::parse_drift_report: a manifest that cannot be trusted to describe
         *          the signatures faithfully is rejected whole rather than partially applied. A raw prepass rejects any
         *          identity collision before the case-sensitive backend reads the (now unambiguous) text, so no merged
         *          or swallowed record can masquerade as another. A missing optional key falls back to its default (an
         *          absent `revision` is 0, unversioned); a key that is present must parse, so a blank enum, numeric,
         *          or boolean value is MalformedLine rather than a default, while a blank string-valued key reads as
         *          empty.
         * @note Setup/control-plane only: parses and allocates bounded manifest state.
         */
        [[nodiscard]] Result<Manifest> parse(std::string_view text,
                                             const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Serializes a manifest to INI text, rejecting anything that could not round-trip.
         * @param manifest The header (its @ref ManifestHeader::revision is emitted when non-zero) and records to emit.
         * @param limits The resource caps to enforce; the default is @ref ManifestLimits::conservative().
         * @return The manifest text, round-trippable through @ref parse, or an Error: InvalidArg (a record whose label
         *         or a string field cannot be framed, an out-of-range persisted enum, or a binding carrying a
         *         non-default inert field), ManifestIdentityCollision (two records whose labels fold to one section,
         *         or a record whose label folds into another record's rung section), SizeTooLarge (encoded text, a
         *         record, rung, field, or aggregate exceeding @p limits), or OutOfMemory. The `schema` line always
         *         reflects this build's @ref SCHEMA_VERSION.
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
        [[nodiscard]] Result<Manifest> load(const std::filesystem::path &path,
                                            const ManifestLimits &limits = ManifestLimits::conservative());

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
         * @details Encoding is validated before the file is opened, so a manifest that could not round-trip never
         *          reaches disk. The write itself truncates @p path in place and is not atomic across a crash or a
         *          failure during the write phase; a torn write is reported by the next @ref load. Durable temp-file
         *          replacement is deliberately out of scope: a torn file fails the next load closed (the caller's
         *          trusted generation and in-code defaults stay in effect), and a caller that needs crash-durable
         *          replacement can stage @ref serialize_checked output through its own temporary file and rename.
         * @note Setup/control-plane only: performs bounded serialization and file I/O.
         */
        [[nodiscard]] Result<void> save(const std::filesystem::path &path, const Manifest &manifest,
                                        const ManifestLimits &limits = ManifestLimits::conservative());

        /**
         * @brief Merges a mod's in-code anchor defaults with optional file overrides, keyed by label.
         * @param defaults The in-code baseline: the anchors the mod always has. Their views are copied, so the caller's
         *                 table need not outlive the returned signatures.
         * @param overrides The file records (typically from @ref load); an empty span passes the defaults through
         *                  untouched.
         * @return The merged, compiled signatures in @p defaults order. A per-signature problem never fails the whole
         *         overlay (fail-soft); the Result carries a failure only if a future merge-wide error mode is added.
         * @note Setup/control-plane only, and not noexcept: like the resolvers it drives, its sole throwing path is
         *       allocation failure. A bad file entry does not throw or fail; it falls back to the in-code default.
         * @details The adoption model in one call, following the same fail-soft discipline @ref config::bind uses for
         *          settings: a default in code, an optional file value that overrides it, a fall back to the default
         *          when the file entry is bad.
         *          - A default with no same-label override is adopted as-is (@ref Signature::adopt).
         *          - A default with a same-label override is replaced by the file (@ref Signature::compile), so a
         *            game update that broke two of twenty signatures needs only those two file entries.
         *          - A malformed override (uncompilable ladder) falls back to the in-code default and is skipped rather
         *            than dropped, so an override never makes things worse than not shipping the file.
         *          - An override whose label matches no default is inert (nothing in code queries it) and is not
         *            included: the file overrides labels the code already knows about.
         *          A default whose kind is the non-serializable Quorum / CallArgHome / Unset, or whose required
         *          evidence is empty, cannot be adopted and is skipped; resolve and gate non-serializable anchors
         *          directly in code through @ref anchor::evaluate_gate.
         */
        [[nodiscard]] Result<std::vector<Signature>> overlay(std::span<const anchor::Anchor> defaults,
                                                             std::span<const SignatureRecord> overrides);

        /**
         * @struct GatePolicy
         * @brief The trust thresholds @ref resolve_and_gate applies. Defaults reject drift but tolerate an unset
         *        baseline.
         */
        struct GatePolicy
        {
            /**
             * @brief When true (the default), a signature whose fingerprint no longer matches its captured baseline is
             *        safe-disabled, because its declared definition was edited without re-capturing, so the edited
             *        binding is unverified and cannot be trusted.
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
             *        mutation, and the binding kind must match the resolved domain -- a MidHook needs a code site, a
             *        VmtMethod a vtable, and an Address / pointer chain a CodeSite or DataAddress, never a vtable or
             *        Scalar. The default false leaves a read-only manifest free to carry a Manual or value-only
             *        binding.
             */
            bool require_mutation_safe_binding = false;

            /**
             * @brief The strictest gate: reject drift, reject an unset baseline, and require every signature to
             * resolve.
             * @details The security-conscious posture, opposite the lenient default. The default GatePolicy trusts a
             *          signature with no captured fingerprint (so an author who has not captured baselines yet is not
             *          blocked) and imposes no whole-manifest floor. This preset inverts both: an unset baseline is
             *          treated as untrusted, and the manifest passes only when the ENTIRE set is trusted
             *          (min_resolved_fraction 1.0), so a single drifted or unresolved feature safe-disables the whole
             *          manifest. It is additive and opt-in -- the default-constructed GatePolicy is unchanged, so a
             *          caller that wants "unknown means trusted" keeps it simply by not opting in.
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
             * @brief The strict gate PLUS mutation-authorization safety, for a manifest that drives an actual patch.
             * @details On top of @ref strict()'s full-resolution, drift-reject, and unset-reject posture, this adds
             *          @ref require_mutation_safe_binding: a signature authorizes a live write only when its binding
             *          matches the resolved @ref anchor::ResultDomain and its kind is not a self-heal-incapable Manual.
             *          A RIP-data anchor bound as a mid-hook, a data address bound as a VMT method, or a Manual literal
             *          authorizing a write is safe-disabled rather than mutating the wrong target. Compose it where a
             *          manifest installs a hook or writes memory, not for a read-only lookup. Additive and opt-in.
             * @return A GatePolicy equal to @ref strict() with @ref require_mutation_safe_binding true.
             */
            [[nodiscard]] static constexpr GatePolicy mutation_strict() noexcept
            {
                GatePolicy policy = strict();
                policy.require_mutation_safe_binding = true;
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
         * @struct RejectedSignature
         * @brief One safe-disabled signature and why it was not trusted.
         */
        struct RejectedSignature
        {
            /// The signature's key (a view into the source Signature).
            std::string_view label;
            /// The resolve outcome; a non-Resolved status is why locate failed, if it did.
            anchor::AnchorStatus status = anchor::AnchorStatus::Unresolved;
            /**
             * @brief The drift verdict; @ref FingerprintState::Drifted here means "definition edited without recapture,
             *        do not trust".
             */
            FingerprintState fingerprint = FingerprintState::Unset;
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
             *         never present) -- so a consumer that safe-disables a feature finds nothing and does not act.
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
         * @details The fail-safe the manifest depends on. A signature is rejected when its @ref Signature::resolve
         *          does not return a unique @ref anchor::AnchorStatus::Resolved, when its fingerprint drifted under
         *          @ref GatePolicy::reject_on_fingerprint_drift (or is unset under
         *          @ref GatePolicy::reject_unset_fingerprint), or when the whole-manifest trusted fraction falls below
         *          @ref GatePolicy::min_resolved_fraction. A rejected feature does not install its hook or read its
         *          pointer; it stays off. This is the trust boundary that turns a silent wrong-address read into an
         *          observable safe-disable.
         * @note Setup/control-plane only: resolving a manifest walks each signature's scope.
         */
        [[nodiscard]] GateResult resolve_and_gate(std::span<const Signature> signatures, const GatePolicy &policy = {},
                                                  Region scope = Region::host());

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
    } // namespace manifest
} // namespace DetourModKit

#endif // DETOURMODKIT_MANIFEST_HPP
