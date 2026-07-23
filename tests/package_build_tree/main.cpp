// An add_subdirectory consumer's compile line must carry no trace of the vendored backend or of DMK-internal
// macro choices: no backend header discoverable, no backend static-build macro, no NOMINMAX, no
// platform-version defines. Checked before any include so only this project's own command line can satisfy it.
#if __has_include(<safetyhook.hpp>) || __has_include(<safetyhook/safetyhook.hpp>)
#error "SafetyHook headers are discoverable from a build-tree consumer's include paths."
#endif
#if __has_include(<Zydis/Zydis.h>) || __has_include(<Zycore/Zycore.h>)
#error "Zydis/Zycore headers are discoverable from a build-tree consumer's include paths."
#endif
#if defined(SAFETYHOOK_NO_DLL) || defined(ZYDIS_STATIC_BUILD) || defined(ZYCORE_STATIC_BUILD)
#error "Backend build macros leaked onto a build-tree consumer's compile line."
#endif
#if defined(NOMINMAX) || defined(WINVER) || defined(_WIN32_WINNT)
#error "DetourModKit must not inject platform or macro configuration into consumer translation units."
#endif

#include <DetourModKit.hpp>

// The library never overrides _ITERATOR_DEBUG_LEVEL, so an MSVC Debug consumer must sit at the debug STL's own
// (nonzero) level; level 0 here could only come from a test-only pin on the consumer's compile line.
#if defined(_MSC_VER) && defined(_DEBUG) && _ITERATOR_DEBUG_LEVEL == 0
#error "A test-only _ITERATOR_DEBUG_LEVEL pin leaked into a build-tree Debug consumer."
#endif

// The exported cxx_std_23 compile feature, not a local CMAKE_CXX_STANDARD, must have raised this TU's level.
#if defined(_MSVC_LANG)
static_assert(_MSVC_LANG >= 202302L, "linking DetourModKit must raise the consumer to C++23");
#else
static_assert(__cplusplus >= 202302L, "linking DetourModKit must raise the consumer to C++23");
#endif

int main()
{
    // is_target_hooked reaches the hook engine and therefore proves the safetyhook -> Zydis -> Zycore archives still
    // arrive through $<LINK_ONLY:...> despite the PRIVATE link.
    return DetourModKit::hook::is_target_hooked(DetourModKit::Address{}) ? 1 : 0;
}
