// The installed package must keep the backend invisible and impose no macro on consumer translation units:
// no backend header discoverable, no backend static-build macro, no NOMINMAX, no platform-version defines,
// no test-only STL pin. Checked at compile time so a violation fails this smoke build, not a downstream mod.
#if __has_include(<safetyhook.hpp>) || __has_include(<safetyhook/safetyhook.hpp>)
#error "SafetyHook headers are discoverable from an installed-package consumer's include paths."
#endif
#if __has_include(<Zydis/Zydis.h>) || __has_include(<Zycore/Zycore.h>)
#error "Zydis/Zycore headers are discoverable from an installed-package consumer's include paths."
#endif
#if defined(SAFETYHOOK_NO_DLL) || defined(ZYDIS_STATIC_BUILD) || defined(ZYCORE_STATIC_BUILD)
#error "Backend build macros leaked onto an installed-package consumer's compile line."
#endif
#if defined(NOMINMAX) || defined(WINVER) || defined(_WIN32_WINNT)
#error "DetourModKit must not inject platform or macro configuration into consumer translation units."
#endif

#include <DetourModKit.hpp>

#if defined(_MSC_VER) && defined(_DEBUG) && _ITERATOR_DEBUG_LEVEL == 0
#error "The test-only _ITERATOR_DEBUG_LEVEL pin leaked into an installed-package Debug consumer."
#endif

int main()
{
    static_assert(DMK_VERSION_AT_LEAST(0, 0, 0));

    // Document the canonical null spelling as a compile-time contract. Address deliberately has no implicit
    // integer constructor, so a bare `0` is ambiguous between the uintptr_t and nullptr_t constructors and must
    // not be used; `Address{}` (or `Address{nullptr}`) is the null address. Keeping this here means the smoke also
    // guards that ergonomics decision against regression from a consumer's toolchain.
    static_assert(DetourModKit::Address{}.raw() == 0, "Address{} must be the null address.");

    if (DetourModKit::hook::is_target_hooked(DetourModKit::Address{}))
    {
        return 1;
    }

    // Exercise the lifecycle surface end to end: start a Session for the current process (no gate, no
    // single-instance guard), then let it destruct to run the ordered teardown. This links the whole Session +
    // subsystem-teardown path.
    if (auto session = DetourModKit::Session::start(DetourModKit::ModInfo{}); !session.has_value())
    {
        return 2;
    }
    // The synchronous path never ran bootstrap(), so this pins the documented idempotence: a drain with no bootstrap
    // worker to retire reports success rather than an error a consumer would have to special-case. It also proves the
    // installed package exports the symbol, which the header-only static_assert in test_session_header.cpp cannot.
    if (!DetourModKit::shutdown_and_wait())
    {
        return 3;
    }

    // Drive Scope's ownership path against the installed archive: add() is where the container is allocated and
    // size()/~Scope read it back, so an inert guard links and exercises add / clear rather than asserting a constant.
    DetourModKit::input::Scope bindings;
    bindings.add(DetourModKit::input::BindingGuard{});
    if (bindings.size() != 1)
    {
        return 4;
    }
    bindings.clear();
    if (bindings.size() != 0)
    {
        return 5;
    }

    // Compile and link the concrete RTTI cache layouts through the installed headers and static archive.
    DetourModKit::rtti::PointerTableCache pointer_table_cache;
    pointer_table_cache.reset();
    DetourModKit::rtti::TypeIdentity identity{".?AVPackageSmoke@@", DetourModKit::Region{}};
    identity.invalidate();
    DetourModKit::rtti::HealedSlot healed_offset;
    healed_offset.seed_nominal(0);
    if (healed_offset.load().validity != DetourModKit::rtti::OffsetValidity::Unverified)
    {
        return 6;
    }

    // Round-trip a one-record manifest through the installed checked encoder and bounded parser.
    {
        namespace mf = DetourModKit::manifest;
        mf::SignatureRecord record;
        record.label = "package.smoke";
        record.kind = DetourModKit::anchor::AnchorKind::Manual;
        record.manual_value = 0x1234;
        mf::Manifest manifest;
        manifest.records.push_back(record);
        const auto encoded = mf::serialize_checked(manifest);
        if (!encoded.has_value())
        {
            return 7;
        }
        const auto parsed = mf::parse(*encoded, mf::ManifestLimits::conservative());
        if (!parsed.has_value() || parsed->records.size() != 1)
        {
            return 8;
        }
    }
    return 0;
}
