// Every public header must compile in a consumer TU that includes <windows.h> first, without NOMINMAX:
// DetourModKit does not export NOMINMAX, so its headers may not rely on a consumer scrubbing the platform
// macro soup. On MSVC, minwindef.h defines the function-like min/max macros in C++ TUs, so this compile is
// the live proof that every public-header spelling survives them (mingw-w64 guards those two behind
// #ifndef __cplusplus, so on MinGW this TU proves the rest of the macro surface; forcing min/max there would
// only test libstdc++, which is not macro-hardened and not DetourModKit's to fix). The textual gate in
// scripts/check_header_hygiene.py guards the min/max-fragile spellings on every platform.
#ifdef NOMINMAX
#error "NOMINMAX reached this TU's compile line; the macro-activity proof would be vacuous."
#endif
#include <windows.h>

#if defined(_MSC_VER) && (!defined(min) || !defined(max))
#error "The Windows min/max macros are not active; the macro-activity proof would be vacuous."
#endif

#include <DetourModKit.hpp>

static_assert(DetourModKit::Address{}.raw() == 0, "The public umbrella must remain usable after <windows.h>.");
