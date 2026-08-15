# Owns DetourModKit's warning and hardening flag lists so each list is stated once and applied per owner:
# target-scoped on the shipped library and the vendored backend archives in the root CMakeLists, and
# directory-scoped over the first-party proof tree in tests/. Nothing here touches the exported interface;
# the consumer-facing hardening link switches stay on the DetourModKit INTERFACE in the root CMakeLists.
include_guard(GLOBAL)

include(CheckCXXCompilerFlag)

if(MSVC)
  set(DMK_WARNING_COMPILE_OPTIONS /W4)

  if(DMK_WARNINGS_AS_ERRORS)
    list(APPEND DMK_WARNING_COMPILE_OPTIONS /WX)
  endif()

  # Control Flow Guard instrumentation. The link-side switches activate the CFG load config and are meaningful
  # only on link steps (executables, DLLs); a static archive records no link options.
  set(DMK_HARDENING_COMPILE_OPTIONS /guard:cf)
  set(DMK_HARDENING_LINK_OPTIONS /DYNAMICBASE /NXCOMPAT /GUARD:CF)
else()
  set(DMK_WARNING_COMPILE_OPTIONS -Wall -Wextra -Wpedantic -Wshadow)

  # -Wdangling-reference (GCC 13+) flags a reference bound to a temporary destroyed at the end of the full
  # expression: the failure mode of this library's by-value view seams (OwnedScanRequest -> ScanRequest, the
  # Region/Pattern by-value accessors). The spelling is GCC-only, so probe for acceptance instead of
  # hardcoding it; check_cxx_compiler_flag treats "unknown warning option" as a rejection, so Clang and older
  # GCC never receive the flag and DMK_WARNINGS_AS_ERRORS cannot escalate a -Wunknown-warning-option into a
  # configure failure. COMPILE_LANGUAGE:CXX keeps the C++-only flag off any C sources sharing a directory
  # scope this list is applied to.
  check_cxx_compiler_flag("-Wdangling-reference" DMK_HAS_WDANGLING_REFERENCE)

  if(DMK_HAS_WDANGLING_REFERENCE)
    list(APPEND DMK_WARNING_COMPILE_OPTIONS $<$<COMPILE_LANGUAGE:CXX>:-Wdangling-reference>)
  endif()

  if(DMK_WARNINGS_AS_ERRORS)
    list(APPEND DMK_WARNING_COMPILE_OPTIONS -Werror)
  endif()

  # ASLR and DEP (NX) for MinGW link steps. GCC has no compile-side CFG counterpart here.
  set(DMK_HARDENING_COMPILE_OPTIONS "")
  set(DMK_HARDENING_LINK_OPTIONS -Wl,--dynamicbase -Wl,--nxcompat)
endif()
