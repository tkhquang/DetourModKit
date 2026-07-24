cmake_minimum_required(VERSION 3.28)

project(DetourModKit VERSION 4.0.0 LANGUAGES CXX)

# GNUInstallDirs defines CMAKE_INSTALL_LIBDIR / BINDIR / INCLUDEDIR / DOCDIR. It must be included before any
# install() rule reads those variables; otherwise they expand to empty and components land at the install-prefix
# root instead of lib/, bin/, include/. The install rules and the package-config block below all depend on it.
include(GNUInstallDirs)

# --- Standard and Compiler Options ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BUILD_SHARED_LIBS OFF) # Build DetourModKit as a static library

# CMAKE_POSITION_INDEPENDENT_CODE is intentionally not set here.
# On Windows (PE/COFF), all code is position-independent by default;
# -fPIC is a no-op on MinGW and ignored by MSVC.

# Make CRT linkage explicit and overridable by consumers.
# Default: dynamic CRT (/MD Release, /MDd Debug).
if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

# --- Compiler Flags ---
option(DMK_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

# Optional build components; their test/benchmark wiring lives next to add_subdirectory(tests). Neither option may
# alter the library's exported usage requirements or ABI: tests/package_build_tree and the release export-equality
# gate hold DMK_BUILD_TESTS ON and OFF to the identical installed contract.
option(DMK_BUILD_TESTS "Build unit tests" OFF)
option(DMK_BUILD_BENCHMARKS "Build benchmark executables" OFF)

if(MSVC)
  add_compile_options(/W4)

  if(DMK_WARNINGS_AS_ERRORS)
    add_compile_options(/WX)
  endif()

  # Security hardening: ASLR, DEP, and Control Flow Guard
  add_link_options(/DYNAMICBASE /NXCOMPAT /GUARD:CF)
  add_compile_options(/guard:cf)

  # The debug STL runs at its default iterator-debug level; DMK never overrides _ITERATOR_DEBUG_LEVEL, in any
  # configuration, so the library's Debug ABI is exactly what a stock /MDd consumer expects. The out-of-memory
  # contracts that MSVC's debug-STL hidden _Container_proxy allocations would derail are proven on libstdc++ (every
  # config) and on the MSVC release STL, which is naturally proxy-free; see DMK_REQUIRE_PROXY_FREE_STL in
  # tests/test_alloc_probe.hpp.

  # Embed CodeView debug info directly into the .obj files (/Z7) for every config, Debug and Release alike. Embedding
  # (rather than a separate .pdb) avoids PDB file-locking contention during parallel builds, and it is the only scheme
  # that actually ships symbols in a STATIC library: an archive has no linker step, so a separate-PDB build would leave
  # the CodeView data in a compiler-side .pdb the .lib does not carry, and the shipped archive would symbolize to bare
  # addresses in a consumer's crash frames. With /Z7 the line and symbol info travels inside the shipped .lib, so a
  # crash in DMK code resolves to file:line for the consumer. The cost is a larger Release archive; the debug info is
  # CodeView, not toolset-locked LTCG IL, so it does not reintroduce the cross-toolset link failure the LTO gate below
  # guards against. RelWithDebInfo/MinSizeRel inherit the same embedded format, which is what a symbolizable build wants.
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "Embedded")
  set(CMAKE_COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pdb")

# Suppress noisy MSVC warnings:
# add_compile_options(/wd4324) # suppressed at source in internal/async_logger_queue.hpp
# add_compile_options(/wd4251) # class 'type' needs to have dll-interface...
# add_compile_options(/wd4275) # non dll-interface class 'type' used as base...
else()
  # GCC/Clang specific flags
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)

  # -Wdangling-reference (GCC 13+) flags a reference bound to a temporary that is destroyed at the end of the
  # full expression. That is precisely the failure mode of the by-value view seams in this library: the
  # OwnedScanRequest -> ScanRequest borrow, the Region/Pattern accessors that return by value, and any
  # `const auto& r = returns_by_value();` in a consumer. The option is a GCC-only spelling: Clang rejects the
  # exact name (it diagnoses the same class of bug under -Wdangling, which is on by default) and GCC before 13
  # does not know it either. Probe for acceptance instead of hardcoding it so Clang and older GCC keep building
  # warning-clean; check_cxx_compiler_flag treats the "unknown warning option" diagnostic as a rejection, so a
  # non-supporting compiler simply does not receive the flag and DMK_WARNINGS_AS_ERRORS cannot escalate a
  # -Wunknown-warning-option into a hard configure failure. The flag is guarded with COMPILE_LANGUAGE:CXX
  # because this directory-scoped option is also inherited by the vendored Zydis/Zycore C sources added below,
  # and cc1 emits a "valid for C++ but not for C" note for every C translation unit otherwise; the guard keeps
  # the flag on DetourModKit's own C++ objects (a C++-only concept anyway) and off the C dependency build.
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-Wdangling-reference" DMK_HAS_WDANGLING_REFERENCE)

  if(DMK_HAS_WDANGLING_REFERENCE)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wdangling-reference>)
  endif()

  if(DMK_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
  endif()

  # Security hardening: ASLR and DEP (NX) for MinGW targets
  add_link_options(-Wl,--dynamicbase -Wl,--nxcompat)

  # The scan engine's SSE2/AVX2 intrinsics are already hand-optimized and do
  # not benefit from -O3's aggressive loop unrolling and auto-vectorization;
  # the scan engine downgrade to -O2 is applied per-source below so the
  # rest of the tree keeps -O3 (hot paths in logger/memory integer math
  # measurably benefit).

  # Suppress specific GCC/Clang warnings if they are noisy or from dependencies
  # add_compile_options(-Wno-unused-parameter -Wno-missing-field-initializers)
endif()

# Coverage must be available before the library target is defined; test helpers are consumed by the optional test tree.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(DMKCoverage)
include(DMKTesting)
include(DMKBackendPatch)

# --- C++23 standard-library feature probes ---
# DetourModKit's public contract is built directly on three C++23 *library* facilities:
#   * std::expected           (<expected>)   -- the Result<T> error-as-value type every fallible API returns.
#   * std::move_only_function (<functional>) -- the type-erased, move-only callback storage in the Session
#                                               bootstrap surface and the RTTI dissection visitors.
#   * std::format             (<format>)     -- the formatting layer beneath the logger and diagnostics.
# target_compile_features(... cxx_std_23) below enforces the *language* level, but a toolchain can accept
# -std=c++23 while shipping a standard library that predates one of these headers; older libstdc++/libc++
# pairings do exactly that. Without an explicit gate such a toolchain fails deep inside the first public
# header with an opaque "no member named 'expected' in namespace std" error that points at library code
# rather than the real cause. Probe each feature-test macro at configure time so an under-provisioned
# standard library is reported once, by name, with a minimum toolchain, before any object is compiled.
include(CheckCXXSourceCompiles)

# The probes must see the same C++23 level the library is built at. try_compile honours CMAKE_CXX_STANDARD /
# CMAKE_CXX_STANDARD_REQUIRED / CMAKE_CXX_EXTENSIONS (CMP0067 is NEW under this file's cmake_minimum_required),
# and those variables are set above, so every probe already compiles as strict C++23 with no per-check flag
# override.
function(_dmk_require_library_feature header macro feature min_toolchain)
  # A bare include of the header plus a preprocessor assertion on its feature-test macro is sufficient: the
  # probe fails if the header is missing entirely, and also if the library ships the header but has not yet
  # implemented (and therefore does not advertise) the feature.
  check_cxx_source_compiles(
    "#include <${header}>
     #ifndef ${macro}
     #error feature-test macro not defined
     #endif
     int main() { return 0; }"
    ${macro}_present)

  if(NOT ${macro}_present)
    message(FATAL_ERROR
      "DetourModKit requires the C++23 library facility ${feature} (${macro}, from <${header}>), but the "
      "configured standard library does not provide it. A compiler that accepts -std=c++23 is not enough; the "
      "standard library must implement the facility too. Upgrade the standard library to at least ${min_toolchain}.")
  endif()
endfunction()

_dmk_require_library_feature(expected   __cpp_lib_expected           "std::expected"           "GCC 12+, MSVC 19.33+ (VS 2022 17.3), or libc++ 16+")
_dmk_require_library_feature(functional __cpp_lib_move_only_function "std::move_only_function" "GCC 12+ or MSVC 19.32+ (VS 2022 17.2)")
_dmk_require_library_feature(format     __cpp_lib_format             "std::format"             "GCC 13+, MSVC 19.29+ (VS 2019 16.10), or libc++ 17+")

# --- Dependencies ---
# SimpleIni will be added as an include directory directly to the DetourModKit target.

# SafetyHook (built from submodule using add_subdirectory)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/safetyhook/CMakeLists.txt")
  message(STATUS "Configuring SafetyHook from submodule: external/safetyhook")

  # The submodule is pinned to an upstream-served commit; DMK's backend fixes are re-applied here from
  # cmake/safetyhook_patches/ before SafetyHook's own CMake reads its sources. Idempotent and fail-closed;
  # see cmake/DMKBackendPatch.cmake and AGENTS.md [B-01].
  dmk_apply_backend_patches(
    "${CMAKE_CURRENT_SOURCE_DIR}/external/safetyhook"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/safetyhook_patches")

  # Set options for SafetyHook's CMake build BEFORE calling add_subdirectory. SAFETYHOOK_FETCH_ZYDIS is a plain
  # cache default (no FORCE) so a packager can pre-set it OFF and satisfy the dependency with a system Zydis via
  # find_package; the dependency-archive collection below already guards on real targets for that route.
  set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "Let SafetyHook manage fetching and building Zydis")
  set(SAFETYHOOK_BUILD_TEST OFF CACHE BOOL "Disable building SafetyHook's internal tests" FORCE)
  set(SAFETYHOOK_BUILD_EXAMPLES OFF CACHE BOOL "Disable building SafetyHook's examples" FORCE)

  # Resolve a packager-provided Zydis in this directory so its imported Zydis/Zycore targets remain visible to the
  # dependency-archive install rules. SafetyHook's repeated find_package call reuses the same targets.
  if(NOT SAFETYHOOK_FETCH_ZYDIS)
    find_package(Zydis REQUIRED CONFIG)
  endif()

  # Pin the fetched Zydis to the immutable commit behind its v4.1.0 tag. SafetyHook's CPM fetch names the mutable
  # tag; FetchContent honours the FIRST declaration of a content name, so declaring it here -- above the
  # add_subdirectory -- decides what that fetch downloads without editing vendored source. A commit hash cannot be
  # moved the way a tag can, and Zycore rides along as a submodule gitlink of this exact Zydis commit. No
  # GIT_SHALLOW: shallow fetch of an arbitrary commit is not reliably served. Inert when SAFETYHOOK_FETCH_ZYDIS is
  # OFF (the declaration is never made available).
  include(FetchContent)
  FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG 569320ad3c4856da13b9dbf1f0d9e20bda63870e # v4.1.0
    EXCLUDE_FROM_ALL SYSTEM)

  # --- Compile Definitions (before add_subdirectory so SafetyHook sees them) ---
  # These are intentionally global (not target-scoped) because SafetyHook's
  # public headers use these macros in #ifdef guards for DLL export/import
  # decorations. If scoped only to DetourModKit, SafetyHook's own compilation
  # would not see them, causing mismatched header expectations. WINVER and
  # _WIN32_WINNT must also be consistent across all translation units so
  # SafetyHook and Zydis target the same Windows API surface.
  if(WIN32)
    add_compile_definitions(
      WINVER=0x0A00 # Target Windows 10 or later
      _WIN32_WINNT=0x0A00 # Target Windows 10 or later
    )
  endif()

  # Definitions for static linking against SafetyHook and Zydis/Zycore.
  add_compile_definitions(
    SAFETYHOOK_NO_DLL # SafetyHook: suppress dllimport/dllexport decorations
    ZYDIS_STATIC_BUILD # Zydis: link as static library
    ZYCORE_STATIC_BUILD # Zycore: link as static library
  )

  # SafetyHook and its dependencies (Zydis, Zycore) should also be built as static libraries.
  # Setting BUILD_SHARED_LIBS to OFF globally (done above) should influence this for
  # well-behaved CMake subprojects. Explicit definitions below will reinforce this.
  #
  # EXCLUDE_FROM_ALL keeps the backend out of the install prefix. SafetyHook's own CMakeLists registers
  # unconditional install() rules for its headers, its lib/cmake/safetyhook export set, and its archives, with no
  # SAFETYHOOK_INSTALL toggle to disable them. Adding the subdirectory with EXCLUDE_FROM_ALL causes CMake to ignore
  # every install() rule defined in it (and below, so Zydis/Zycore too) when installing DetourModKit's prefix, so the
  # backend is never advertised: no include/safetyhook*, no find_package(safetyhook)-satisfiable config. The backend
  # is still built here because DetourModKit links it, and an inter-target dependency supersedes the ALL exclusion.
  # DetourModKit ships the dependency archives itself, as plain files, through the DetourModKit::deps imported target
  # (see the per-dependency install(FILES ... RENAME) rules below), so a find_package consumer still links the static chain.
  # SYSTEM suppresses compiler warnings from the external headers.
  add_subdirectory(external/safetyhook EXCLUDE_FROM_ALL SYSTEM)

  # Suppress all warnings when compiling external dependency sources
  foreach(_ext_target safetyhook Zydis Zycore)
    if(TARGET ${_ext_target})
      target_compile_options(${_ext_target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-w>
        $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-w>
        $<$<CXX_COMPILER_ID:MSVC>:/w>
        $<$<C_COMPILER_ID:MSVC>:/w>
      )
    endif()
  endforeach()

  # Define the CMake target name that SafetyHook's build produces for its main library.
  set(SAFETYHOOK_LIBRARY_TARGET_NAME safetyhook)
else()
  message(FATAL_ERROR "SafetyHook submodule not found at 'external/safetyhook'. "
    "Please ensure submodules are initialized and updated: "
    "'git submodule update --init --recursive'")
endif()

# DirectXMath (header-only library from submodule).
# DetourModKit itself does not use DirectXMath in any of its own headers or sources; it is vendored and re-exported
# as a deliberate convenience so consuming mods can `#include <DirectXMath.h>` (game camera/vector math) without
# wiring their own submodule. The PUBLIC include interface and the header install below ship it to find_package
# consumers for that reason. This is intentional: dropping it is a breaking change for any downstream that relies
# on the transitive include path.
#
# The re-export is on by default so existing consumers keep the transitive include path unchanged. A packager who
# wants a prefix that ships only DetourModKit's own public headers (no vendored third-party tree) can turn it off.
# Because the library never includes DirectXMath in its own build, the switch is purely an install/interface concern:
# it gates only whether the vendored headers and the install-interface include directory reach find_package consumers,
# and never affects DetourModKit's own compilation or the build-tree (add_subdirectory) include path.
option(DMK_INSTALL_DIRECTXMATH "Install and re-export the vendored DirectXMath headers to find_package consumers" ON)
set(DIRECTXMATH_INCLUDE_DIR "")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/DirectXMath/Inc/DirectXMath.h")
  set(DIRECTXMATH_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/DirectXMath/Inc")
  message(STATUS "DirectXMath found at: ${DIRECTXMATH_INCLUDE_DIR}")
else()
  message(FATAL_ERROR "DirectXMath submodule not found at 'external/DirectXMath'. "
    "Please ensure submodules are initialized and updated: "
    "'git submodule update --init --recursive'")
endif()

# --- Version Header Generation ---
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit/version.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/DetourModKit/version.hpp"
  @ONLY
)

# --- Static analysis (clang-tidy, opt-in advisory) ---
# The curated .clang-tidy at the repo root is advisory: it never fails a build (WarningsAsErrors: '') and confines
# header diagnostics to include/DetourModKit via HeaderFilterRegex. This option wires it into the build so clang-tidy
# runs alongside compilation of DetourModKit's own sources (and the tests). Off by default so normal consumer and CI
# builds are unaffected; CI runs it in a continue-on-error lane. Set here -- after the external submodules are added
# above and before the library and test targets below -- so only this project's targets inherit the launcher
# and SafetyHook / Zydis / Zycore are never analysed.
option(DMK_ENABLE_CLANG_TIDY "Run clang-tidy on DetourModKit sources during the build (advisory)" OFF)

if(DMK_ENABLE_CLANG_TIDY)
  find_program(DMK_CLANG_TIDY_EXE NAMES clang-tidy)
  if(DMK_CLANG_TIDY_EXE)
    # Export compile_commands.json too, so a standalone `clang-tidy -p <build>` run can reuse the same flags.
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(DMK_CLANG_TIDY_COMMAND "${DMK_CLANG_TIDY_EXE}")
    # clang-tidy runs its own clang frontend. Under a GCC (MinGW) compiler on Windows it otherwise defaults to the
    # LLVM/MSVC target triple and fails to parse the MinGW headers and the GCC SIMD target attributes, so pin
    # clang-tidy's target to the compiler's own triple (from `g++ -dumpmachine`). MSVC selects clang-cl driver mode
    # automatically, so this adjustment is confined to the GNU toolchain.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      execute_process(COMMAND "${CMAKE_CXX_COMPILER}" -dumpmachine
        OUTPUT_VARIABLE DMK_GCC_TRIPLE OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
      if(DMK_GCC_TRIPLE)
        list(APPEND DMK_CLANG_TIDY_COMMAND "--extra-arg-before=--target=${DMK_GCC_TRIPLE}")
      endif()
    endif()
    set(CMAKE_CXX_CLANG_TIDY ${DMK_CLANG_TIDY_COMMAND})
    message(STATUS "clang-tidy enabled (advisory): ${DMK_CLANG_TIDY_COMMAND}")
  else()
    message(WARNING "DMK_ENABLE_CLANG_TIDY=ON but no clang-tidy binary was found on PATH; static analysis skipped.")
  endif()
endif()

# --- DetourModKit Library Target Definition ---
# Glob source files. CONFIGURE_DEPENDS re-globs on CMakeLists changes so a newly added src/*.cpp is picked up without a
# manual re-run on the generators that honour it (Ninja, Makefiles). The glob result is then cross-checked against a
# checked-in manifest below so the source set can never silently drift.
file(GLOB DETOURMODKIT_SOURCE_FILES
  CONFIGURE_DEPENDS
  "src/*.cpp"
  "src/internal/*.cpp"
)

if(NOT DETOURMODKIT_SOURCE_FILES)
  message(FATAL_ERROR "No C++ source files found in 'src/*.cpp' / 'src/internal/*.cpp' for the DetourModKit library.")
endif()

# Cross-check the globbed source set against the reviewed manifest and fail the configure closed on any drift. A bare
# file(GLOB) is invisible in review -- a new translation unit changes no tracked CMake text, so a reviewer never sees it
# was added, and a stale CONFIGURE_DEPENDS cache (or a generator that ignores it) can silently drop it, surfacing only
# as a consumer-side LNK2019 against the missing symbol. Pinning the set to cmake/source_manifest.txt makes every
# add/remove a reviewable diff. The manifest is authored repo-relative with forward slashes; normalize the glob the same
# way and compare as sorted lists so ordering never matters.
set(_dmk_globbed_sources "")
foreach(_src IN LISTS DETOURMODKIT_SOURCE_FILES)
  file(RELATIVE_PATH _rel "${CMAKE_CURRENT_SOURCE_DIR}" "${_src}")
  list(APPEND _dmk_globbed_sources "${_rel}")
endforeach()
list(SORT _dmk_globbed_sources)

set(_dmk_manifest_file "${CMAKE_CURRENT_SOURCE_DIR}/cmake/source_manifest.txt")
if(NOT EXISTS "${_dmk_manifest_file}")
  message(FATAL_ERROR "Source manifest '${_dmk_manifest_file}' is missing; it must list every library source file.")
endif()
file(STRINGS "${_dmk_manifest_file}" _dmk_manifest_lines)
set(_dmk_manifest_sources "")
foreach(_line IN LISTS _dmk_manifest_lines)
  string(STRIP "${_line}" _line)
  if(_line STREQUAL "" OR _line MATCHES "^#")
    continue()
  endif()
  list(APPEND _dmk_manifest_sources "${_line}")
endforeach()
list(SORT _dmk_manifest_sources)

if(NOT _dmk_globbed_sources STREQUAL _dmk_manifest_sources)
  # Compute the two-way difference so the diagnostic names exactly what to add or remove. The manifest side is guarded
  # because a manifest of only comments/blank lines parses to an empty list, and list(REMOVE_ITEM) with no value
  # arguments is a hard error; the glob side needs no such guard because the fail-closed check above already halts
  # configure on an empty glob, so _dmk_globbed_sources is always non-empty here.
  set(_dmk_missing_from_manifest ${_dmk_globbed_sources})
  if(_dmk_manifest_sources)
    list(REMOVE_ITEM _dmk_missing_from_manifest ${_dmk_manifest_sources})
  endif()
  set(_dmk_missing_from_disk ${_dmk_manifest_sources})
  list(REMOVE_ITEM _dmk_missing_from_disk ${_dmk_globbed_sources})
  message(FATAL_ERROR
    "DetourModKit source-set drift: the glob of src/ does not match cmake/source_manifest.txt.\n"
    "  On disk but NOT in the manifest (add these): ${_dmk_missing_from_manifest}\n"
    "  In the manifest but NOT on disk (remove these): ${_dmk_missing_from_disk}\n"
    "Update cmake/source_manifest.txt to match, then reconfigure.")
endif()

# Define the DetourModKit static library target
add_library(DetourModKit STATIC
  ${DETOURMODKIT_SOURCE_FILES}
)

# Bake the C++23 requirement into the exported/installed target so every find_package(DetourModKit) consumer
# inherits it through INTERFACE_COMPILE_FEATURES (which survives install(EXPORT)). The global CMAKE_CXX_STANDARD
# set above governs the in-tree build of the external submodules and tests; this target feature governs the
# exported contract that the tests/package_smoke consumer proves.
target_compile_features(DetourModKit PUBLIC cxx_std_23)

# Direct instrumentation keeps the build-only coverage target out of the archive's exported interface.
dmk_instrument_for_coverage(DetourModKit)

# NOMINMAX is PRIVATE: DMK's own translation units include <windows.h> and want the min/max macros gone, but no
# public header includes <windows.h>, so consumers gain nothing from the define and must not have a behavior-changing
# macro imposed on every one of their translation units (it silently breaks headers that rely on the macros, e.g.
# <gdiplus.h>). Public headers stay compilable with the macros ACTIVE instead: the windows_macro_probe TUs in
# tests/package_smoke and tests/package_build_tree include <windows.h> without NOMINMAX ahead of every public header.
if(WIN32)
  target_compile_definitions(DetourModKit PRIVATE NOMINMAX)
endif()

# Deterministic lifecycle/cache-race test seams compile into the library ONLY for test builds; a shipping or installed
# archive (DMK_BUILD_TESTS OFF) omits them entirely, so no test-only symbol or branch ships. PRIVATE so the definition
# never enters the exported usage requirements a consumer would inherit.
if(DMK_BUILD_TESTS)
  target_compile_definitions(DetourModKit PRIVATE DMK_ENABLE_TEST_SEAMS)
endif()

# --- Target-Scoped Release Optimizations ---
# Applied per-target so they do not leak into external subdirectory targets.
if(MSVC)
  # /Gy: function-level linking, /Gw: global data optimization.
  # These enable the linker to discard unreferenced code/data via /OPT:REF,ICF.
  target_compile_options(DetourModKit PRIVATE
    $<$<CONFIG:Release>:/Gy /Gw>
  )
else()
  # -ffunction-sections/-fdata-sections + --gc-sections: GCC/Clang equivalent
  # of MSVC's /Gy + /OPT:REF for dead code elimination.
  target_compile_options(DetourModKit PRIVATE
    $<$<CONFIG:Release>:-ffunction-sections -fdata-sections>
  )

  # --gc-sections is INTERFACE so consumers benefit from dead code elimination
  # of unused DetourModKit symbols. Symbol stripping (-s) is deliberately left
  # to the consumer's own build setup.
  target_link_options(DetourModKit INTERFACE
    $<$<CONFIG:Release>:-Wl,--gc-sections>
  )

  # Per-source optimization override: downgrade the scan engine from -O3 to -O2
  # because its SSE2/AVX2 verifier is hand-tuned and -O3 loop unrolling has
  # been observed to pessimize the inner loop. The rest of the library keeps
  # the Release default (-O3 via CMAKE_CXX_FLAGS_RELEASE). Appending -O2
  # after -O3 on the engine's compile line is the effective flag because
  # GCC and Clang resolve repeated -O levels by taking the last one.
  set(_dmk_scanner_src "${CMAKE_CURRENT_SOURCE_DIR}/src/internal/scan_engine.cpp")

  if(EXISTS "${_dmk_scanner_src}")
    set_source_files_properties("${_dmk_scanner_src}"
      TARGET_DIRECTORY DetourModKit
      PROPERTIES COMPILE_OPTIONS "$<$<CONFIG:Release>:-O2>"
    )
  endif()
endif()

# Set output name and prefix properties for consistency
# For most generators (like MinGW Makefiles), PREFIX is "lib" by default for static/shared libs.
# For MSVC, PREFIX is empty by default for static/shared libs.
# We want the output file to be "libDetourModKit.lib" on MSVC.
# And "libDetourModKit.a" on MinGW (which is the default).
set_target_properties(DetourModKit PROPERTIES
  OUTPUT_NAME "DetourModKit"
  # Debug artifacts get a 'd' suffix (libDetourModKitd.a / libDetourModKitd.lib) so a prefix that installs both a Debug
  # and a Release configuration does not have the two archives collide on one file name. install(EXPORT) records the
  # per-config artifact name, so a find_package consumer resolves the archive matching its own configuration. The
  # standalone-link harness scripts prefer the suffixed Debug archive when present and fall back to the legacy
  # unsuffixed name for older or Release build trees.
  DEBUG_POSTFIX "d"
)

if(MSVC)
  set_target_properties(DetourModKit PROPERTIES
    PREFIX "lib" # Force "lib" prefix for MSVC output
  )
  message(STATUS "MSVC: Setting library prefix to 'lib' for DetourModKit.")
else()
  # For GCC/Clang (MinGW), the "lib" prefix is usually default for libraries.
  message(STATUS "Non-MSVC: Default library prefixing will apply (e.g., 'lib' for libDetourModKit.a).")
endif()

# --- Include Directories for DetourModKit ---
target_include_directories(DetourModKit
  PUBLIC

  # For consumers using find_package(DetourModKit) AFTER installation:
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>

  # For consumers using DetourModKit as a subdirectory (BUILD_INTERFACE):
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

  # Generated headers (version.hpp)
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>

  # DirectXMath headers for the build interface (add_subdirectory consumers). The install-interface counterpart is
  # attached separately below, gated on DMK_INSTALL_DIRECTXMATH, so a prefix that opts out of the re-export does not
  # advertise an include path pointing at headers it never installed.
  $<BUILD_INTERFACE:${DIRECTXMATH_INCLUDE_DIR}>

  PRIVATE

  # For DetourModKit's *own sources* (in src/) to find its *public headers*
  "${CMAKE_CURRENT_SOURCE_DIR}/include"

  # For DetourModKit's own sources to find its private engine headers without `../` paths: src/ TUs
  # include "internal/scan_engine.hpp" etc., and src/internal/ TUs include the shared src/ headers
  # ("x86_decode.hpp", "fork_join.hpp"). These headers are never installed.
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

# External dependency headers marked as SYSTEM to suppress their warnings
target_include_directories(DetourModKit SYSTEM
  PUBLIC
  $<BUILD_INTERFACE:${DIRECTXMATH_INCLUDE_DIR}>

  PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/external/simpleini"
  "${DIRECTXMATH_INCLUDE_DIR}"
)

# The DirectXMath install-interface include path is attached only when the re-export is installed, so an opted-out
# prefix never exports an include directory pointing at DirectXMath headers it did not ship. Kept SYSTEM to mirror the
# build-interface DirectXMath include above (external headers, their warnings suppressed for consumers too).
if(DMK_INSTALL_DIRECTXMATH)
  target_include_directories(DetourModKit SYSTEM
    PUBLIC
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/DirectXMath>
  )
endif()

# --- Linking Dependencies for DetourModKit ---
if(TARGET ${SAFETYHOOK_LIBRARY_TARGET_NAME})
  # The backend link is PRIVATE: only DMK's own sources compile against SafetyHook, so its include directories and
  # macros must never reach a consumer's compile line (tests/package_build_tree asserts they do not). Because
  # DetourModKit is a STATIC library, CMake still records the PRIVATE dependency as $<LINK_ONLY:...> in the exported
  # interface, so a build-tree consumer's final link resolves the safetyhook -> Zydis -> Zycore archive chain without
  # inheriting any usage requirement. The INSTALL interface cannot reference those targets (each lives in its own
  # export set); installed consumers link DetourModKit::deps, an imported target the package config defines over the
  # shipped dependency archives.
  target_link_libraries(DetourModKit
    PRIVATE "$<BUILD_INTERFACE:${SAFETYHOOK_LIBRARY_TARGET_NAME}>"
    INTERFACE "$<INSTALL_INTERFACE:DetourModKit::deps>")
  message(STATUS "DetourModKit linked against target: ${SAFETYHOOK_LIBRARY_TARGET_NAME}")
else()
  message(WARNING "SafetyHook library target '${SAFETYHOOK_LIBRARY_TARGET_NAME}' was not found. "
    "DetourModKit may fail to link correctly.")
endif()

# Link necessary system libraries for Windows API calls.
# INTERFACE so consumers of this static library automatically resolve these
# import libraries when linking the final DLL/EXE.
# The XInput import library name differs between toolchains:
# MSVC / Windows SDK: xinput.lib  (links against xinput1_4.dll at runtime)
# MinGW:              -lxinput1_4 (libxinput1_4.a ships with mingw-w64)
if(WIN32)
  if(MSVC)
    set(_DMK_XINPUT_LIB xinput)
  else()
    set(_DMK_XINPUT_LIB xinput1_4)
  endif()

  target_link_libraries(DetourModKit INTERFACE
    user32 # GetAsyncKeyState, GetForegroundWindow, GetWindowThreadProcessId
    ${_DMK_XINPUT_LIB} # XInput gamepad polling (xinput1_4.dll ships with Win8+)
  )

  # Propagate the security-hardening link switches to consumers. The
  # directory-scoped add_link_options() above only hardens targets built in this
  # tree (DetourModKit's own tests/benches). DetourModKit is a static library, so
  # the consumer performs the final link of the mod DLL/EXE; the switches must
  # ride along on the exported INTERFACE to reach that link. ASLR (/DYNAMICBASE,
  # --dynamicbase) and DEP (/NXCOMPAT, --nxcompat) are toolchain defaults but are
  # stated explicitly, and /GUARD:CF activates the Control Flow Guard load config
  # so DetourModKit's /guard:cf-instrumented code is enforced in the consumer
  # binary. CMake's compiler-frontend generator expression is 3.30+, so keep the
  # project compatible with its 3.28 minimum by detecting the active frontend at
  # configure time. Release packages are compiler-specific, and add_subdirectory
  # consumers share the same toolchain that configured this target.
  set(_dmk_uses_msvc_linker_frontend OFF)

  if(MSVC OR "${CMAKE_CXX_SIMULATE_ID}" STREQUAL "MSVC")
    set(_dmk_uses_msvc_linker_frontend ON)
  endif()

  set(_dmk_uses_gnu_linker_frontend OFF)

  if(MINGW OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR
    (CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND NOT _dmk_uses_msvc_linker_frontend))
    set(_dmk_uses_gnu_linker_frontend ON)
  endif()

  if(_dmk_uses_msvc_linker_frontend)
    target_link_options(DetourModKit INTERFACE /DYNAMICBASE /NXCOMPAT /GUARD:CF)
  elseif(_dmk_uses_gnu_linker_frontend)
    target_link_options(DetourModKit INTERFACE -Wl,--dynamicbase -Wl,--nxcompat)
  endif()
endif()

# --- Installation Rules ---
# Define common install component names for clarity and potential partial installs.
set(DETOURMODKIT_LIB_COMPONENT lib) # For the library files (.a, .lib)
set(DETOURMODKIT_DEV_COMPONENT dev) # For development files (headers, CMake config)
set(DETOURMODKIT_DOCS_COMPONENT docs) # For documentation (LICENSE, README)

# DetourModKit is a STATIC library and does not absorb the object code of the
# static dependencies it links (safetyhook -> Zydis -> Zycore); a find_package
# consumer must link those archives too. The dependency targets register their
# own install/export sets, and CMake forbids a transitively-required target from
# living in more than one export set, so they cannot be folded into
# DetourModKitTargets. Instead ship their archives as plain files and expose
# them to consumers through the DetourModKit::deps imported target the package
# config defines (see cmake/DetourModKitConfig.cmake.in). Install each archive
# here and record its installed file name for the config template. Resolve
# aliases and imported package targets so fetched and system-Zydis builds
# produce the same self-contained prefix.
# Order matters: a dependent precedes its dependency for single-pass linkers.
# Configuration-specific dependency archives. A dual-config prefix installs Debug and Release side by side; a
# config-invariant name would let the second `cmake --install --config` overwrite the first, after which a consumer
# could silently cross-link a mismatched-configuration archive (on MSVC an _ITERATOR_DEBUG_LEVEL / CRT mismatch
# surfaces as LNK2038, on MinGW as silent ODR UB). The compiled DetourModKit archive already separates configurations
# through DEBUG_POSTFIX; the dependency archives, shipped as plain files, take the same postfix so the Debug
# (libsafetyhookd.a / safetyhookd.lib) and Release (libsafetyhook.a / safetyhook.lib) sets coexist in one lib/. The
# package config selects the matching name per consumer configuration (see cmake/DetourModKitConfig.cmake.in). The
# Debug and Release-family rules are installed separately because install(FILES) RENAME is a literal, not a generator
# expression; each fires only for its own `--install --config`.
get_target_property(_DMK_DEBUG_POSTFIX DetourModKit DEBUG_POSTFIX)
if(NOT _DMK_DEBUG_POSTFIX)
  message(FATAL_ERROR
    "DetourModKit has no DEBUG_POSTFIX; the dependency archives would collide when Debug and Release install into "
    "one prefix. Restore the target's DEBUG_POSTFIX before shipping a dual-config package.")
endif()

set(_DMK_DEP_ARCHIVE_NAMES_RELEASE "")
set(_DMK_DEP_ARCHIVE_NAMES_DEBUG "")

foreach(_dep_name IN ITEMS ${SAFETYHOOK_LIBRARY_TARGET_NAME} Zydis Zycore)
  set(_dep_target "${_dep_name}")
  if(NOT TARGET "${_dep_target}" AND TARGET "${_dep_name}::${_dep_name}")
    set(_dep_target "${_dep_name}::${_dep_name}")
  endif()
  if(NOT TARGET "${_dep_target}")
    message(FATAL_ERROR "Required dependency target '${_dep_name}' was not provided by SafetyHook/Zydis.")
  endif()

  get_target_property(_dep_aliased "${_dep_target}" ALIASED_TARGET)
  if(_dep_aliased)
    set(_dep_target "${_dep_aliased}")
  endif()

  # DetourModKit::deps can only point at static archives, and only under the exact names the generated package
  # config references. Reject shared or unknown resolutions (a system Zydis built shared would otherwise install
  # a file the config never mentions); RENAME pins the installed name whatever the producing build called it.
  get_target_property(_dep_type "${_dep_target}" TYPE)
  if(NOT _dep_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR
      "Dependency '${_dep_name}' resolved to a ${_dep_type} target; DetourModKit::deps requires static archives. "
      "A system-provided Zydis/Zycore must be built static.")
  endif()

  set(_dep_archive_release "${CMAKE_STATIC_LIBRARY_PREFIX}${_dep_name}${CMAKE_STATIC_LIBRARY_SUFFIX}")
  string(CONCAT _dep_archive_debug
    "${CMAKE_STATIC_LIBRARY_PREFIX}${_dep_name}"
    "${_DMK_DEBUG_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")

  install(FILES "$<TARGET_FILE:${_dep_target}>"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RENAME "${_dep_archive_debug}"
    CONFIGURATIONS Debug
    COMPONENT ${DETOURMODKIT_LIB_COMPONENT})
  # The empty "" configuration is included so a single-config generator with no CMAKE_BUILD_TYPE (which DMK supports
  # and records as "unspecified") still ships the dependency archives, matching install(TARGETS DetourModKit) below,
  # which is unguarded and always installs. Under a Debug install the config is "Debug", so this rule does not also
  # fire (no double-install); the main archive's DEBUG_POSTFIX likewise applies to Debug alone, so every supported
  # non-Debug configuration yields the release-named archive here.
  install(FILES "$<TARGET_FILE:${_dep_target}>"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RENAME "${_dep_archive_release}"
    CONFIGURATIONS "" Release RelWithDebInfo MinSizeRel
    COMPONENT ${DETOURMODKIT_LIB_COMPONENT})

  list(APPEND _DMK_DEP_ARCHIVE_NAMES_RELEASE "${_dep_archive_release}")
  list(APPEND _DMK_DEP_ARCHIVE_NAMES_DEBUG "${_dep_archive_debug}")
endforeach()

# Install the compiled DetourModKit library target.
install(TARGETS DetourModKit
  EXPORT DetourModKitTargets # Associates this target with the DetourModKitTargets export set.
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT ${DETOURMODKIT_LIB_COMPONENT}
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT ${DETOURMODKIT_LIB_COMPONENT}
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT ${DETOURMODKIT_LIB_COMPONENT}
)

# Install public header files.
# Install individual module headers from include/DetourModKit/
file(GLOB _dmk_module_headers_for_install
  LIST_DIRECTORIES false
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit/*.hpp"
)

if(_dmk_module_headers_for_install)
  install(FILES ${_dmk_module_headers_for_install}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DetourModKit"
    COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
  )
else()
  message(WARNING "No module headers found in 'include/DetourModKit/*.hpp' to install.")
endif()

# Install detail/ headers from include/DetourModKit/detail/. These carry compile-visible support (namespace
# DetourModKit::detail) that public headers depend on by value, so they must ship alongside the public surface even
# though consumers never include them directly. scan.hpp holds scan::Pattern by value, whose inline storage and
# constexpr parser are detail/pattern_core.hpp, so that header must ship for an installed package to compile.
file(GLOB _dmk_detail_headers_for_install
  LIST_DIRECTORIES false
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit/detail/*.hpp"
)

if(_dmk_detail_headers_for_install)
  install(FILES ${_dmk_detail_headers_for_install}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DetourModKit/detail"
    COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
  )
endif()

# Install generated version header
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/DetourModKit/version.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DetourModKit"
  COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
)

# The umbrella is the root-level include/DetourModKit.hpp, placed beside (not inside) the include/DetourModKit/ module
# directory so a consumer writes <DetourModKit.hpp> with no doubled path (the Boost.Asio shape: an <asio.hpp> umbrella
# beside the <asio/...> parts). Because it lives one directory above the module-headers glob, it is not swept up by
# that glob and needs its own rule installing it at the include-dir root. The lifecycle surface is session.hpp and is
# installed by the module-header glob above.
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit.hpp"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
)

# Install DirectXMath headers, gated on DMK_INSTALL_DIRECTXMATH. When the re-export is off, nothing DirectXMath ships
# and the install-interface include path attached above is likewise omitted, so an opted-out prefix carries only
# DetourModKit's own public headers rather than a vendored third-party tree.
if(DMK_INSTALL_DIRECTXMATH)
  if(DIRECTXMATH_INCLUDE_DIR AND EXISTS "${DIRECTXMATH_INCLUDE_DIR}")
    file(GLOB _directxmath_headers_for_install
      LIST_DIRECTORIES false
      "${DIRECTXMATH_INCLUDE_DIR}/*.h"
      "${DIRECTXMATH_INCLUDE_DIR}/*.hpp"
      "${DIRECTXMATH_INCLUDE_DIR}/*.inl"
    )

    if(_directxmath_headers_for_install)
      install(FILES ${_directxmath_headers_for_install}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DirectXMath"
        COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
      )
      message(STATUS "DirectXMath headers will be installed from: ${DIRECTXMATH_INCLUDE_DIR}")
    else()
      message(WARNING "No DirectXMath headers found in '${DIRECTXMATH_INCLUDE_DIR}' to install.")
    endif()
  else()
    message(WARNING "DirectXMath include directory not found or empty: ${DIRECTXMATH_INCLUDE_DIR}")
  endif()
else()
  message(STATUS "DirectXMath re-export disabled (DMK_INSTALL_DIRECTXMATH=OFF); the prefix will not ship DirectXMath headers.")
endif()

# --- CMake Package Configuration for Consumers ---
include(CMakePackageConfigHelpers) # Provides helper macros (GNUInstallDirs is included near the top of this file)

# Define a variable for the CMake package configuration install directory.
# Common locations are lib/cmake/<PackageName> or share/cmake/<PackageName>.
set(DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/DetourModKit")

# Create DetourModKitConfigVersion.cmake (records the version of the installed package)
# SameMajorVersion, not AnyNewerVersion. DetourModKit ships clean-break major versions: v4 deleted the entire v3 public
# surface (namespaces, headers, enums), so a v4 consumer's find_package(DetourModKit 4) must NOT be satisfied by a
# future v5 install whose API it cannot compile against. SameMajorVersion accepts an equal-or-newer version within the
# same major (a 4.0 consumer is happy with 4.1) and rejects a cross-major swap, which is exactly the compatibility the
# clean-break policy guarantees. AnyNewerVersion would silently declare a v5 prefix compatible with a v4 request.
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

# Create DetourModKitTargets.cmake for the *installed* package.
# This file allows CMake to import the DetourModKit library target when found by find_package.
install(EXPORT DetourModKitTargets
  FILE DetourModKitTargets.cmake # Name of the file to be generated and installed
  NAMESPACE DetourModKit:: # Namespace for imported targets (e.g., DetourModKit::DetourModKit)
  DESTINATION "${DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR}"
  COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
)

# Record the producing toolchain's ABI axes in a machine-readable file installed beside the package config. A C++
# static archive is only consumable from a compatible compiler ABI, standard library, CRT, iterator-debug level, and
# architecture; the prose contract in DetourModKitConfig.cmake.in states that, and this file states it as data so
# package validation can compare axes instead of trusting the consumer to read. Iterator-debug is recorded as "default"
# because DMK never overrides _ITERATOR_DEBUG_LEVEL in any configuration.
if(MSVC OR "${CMAKE_CXX_SIMULATE_ID}" STREQUAL "MSVC")
  set(DMK_ABI_STL "msvc-stl")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(DMK_ABI_STL "libstdc++")
else()
  set(DMK_ABI_STL "unknown")
endif()

if(DEFINED CMAKE_MSVC_RUNTIME_LIBRARY AND MSVC)
  set(DMK_ABI_MSVC_RUNTIME "${CMAKE_MSVC_RUNTIME_LIBRARY}")
else()
  set(DMK_ABI_MSVC_RUNTIME "")
endif()

get_property(_dmk_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(_dmk_is_multi_config)
  set(DMK_ABI_BUILD_TYPE "multi-config")
elseif(CMAKE_BUILD_TYPE)
  set(DMK_ABI_BUILD_TYPE "${CMAKE_BUILD_TYPE}")
else()
  set(DMK_ABI_BUILD_TYPE "unspecified")
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/DetourModKitAbi.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitAbi.cmake"
  @ONLY
)

# Configure DetourModKitConfig.cmake from the .in template.
# This is the main file consumers use with find_package(DetourModKit).
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/DetourModKitConfig.cmake.in" # Input template
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfig.cmake" # Output in build directory
  INSTALL_DESTINATION "${DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR}" # Where to install the configured file

  # NO_SET_AND_CHECK_MACRO # Add if your .in file provides these macros itself
  # NO_CHECK_REQUIRED_COMPONENTS_MACRO # Add if your .in file handles this
)

# Install the configured DetourModKitConfig.cmake, the version file, and the ABI record.
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfigVersion.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitAbi.cmake"
  DESTINATION "${DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR}"
  COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
)

# Install documentation files (LICENSE, Acknowledgements, README).
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    COMPONENT ${DETOURMODKIT_DOCS_COMPONENT})
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/DetourModKit_Acknowledgements.txt")
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/DetourModKit_Acknowledgements.txt"
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    COMPONENT ${DETOURMODKIT_DOCS_COMPONENT})
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    COMPONENT ${DETOURMODKIT_DOCS_COMPONENT})
endif()

# --- Summary Message (Optional) ---
message(STATUS "---------------------------------------------------------------------")
message(STATUS "DetourModKit (${PROJECT_VERSION}) Configuration Summary:")
message(STATUS "  Generator:                   ${CMAKE_GENERATOR}")
message(STATUS "  Build Type (single-config):  ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix:              ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Install Library Dir:         ${CMAKE_INSTALL_LIBDIR} (relative to prefix)")
message(STATUS "  Install Include Dir:         ${CMAKE_INSTALL_INCLUDEDIR} (relative to prefix)")
message(STATUS "  Install CMake Config Dir:    ${DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR} (potentially relative to prefix)")
message(STATUS "  Install Docs Dir:            ${CMAKE_INSTALL_DOCDIR} (standard path)")
message(STATUS "  DirectXMath Include Dir:    ${DIRECTXMATH_INCLUDE_DIR}")
message(STATUS "---------------------------------------------------------------------")

# --- Profiling ---
option(DMK_ENABLE_PROFILING "Enable profiling instrumentation (opt-in, zero cost when OFF)" OFF)

if(DMK_ENABLE_PROFILING)
  target_compile_definitions(DetourModKit PUBLIC DMK_ENABLE_PROFILING)
  message(STATUS "Profiling instrumentation enabled")
endif()

# --- AVX-512 scanner verify tier ---
# Opt-in, off by default. When ON, the scanner compiles an AVX-512F + AVX-512BW verify tier (64 bytes per iteration)
# selected at runtime behind a CPUID + XGETBV gate. The intrinsics are confined to that one tier via a per-function
# target attribute (GCC/Clang) so the rest of the library stays AVX2-only -- no global /arch:AVX512 or -mavx512 is
# added, and the produced library still runs on CPUs without AVX-512 (the tier is simply never selected). The runtime
# >= 30% throughput gate for this tier can only be measured on an AVX-512 host (see docs/analysis/avx512_verify_icount).
option(DMK_ENABLE_AVX512 "Compile the opt-in AVX-512 scanner verify tier (runtime-gated)" OFF)

if(DMK_ENABLE_AVX512)
  target_compile_definitions(DetourModKit PRIVATE DMK_ENABLE_AVX512)
  message(STATUS "AVX-512 scanner verify tier enabled (runtime-gated by cpu_has_avx512())")
endif()

# --- Sanitizers ---
option(DMK_ENABLE_SANITIZERS "Enable AddressSanitizer (and UBSan on GCC/Clang)" OFF)

if(DMK_ENABLE_SANITIZERS)
  if(MSVC)
    # AddressSanitizer is the only sanitizer available on Windows: UBSan is
    # GCC/Clang-only, and mingw-w64 ships no sanitizer runtime at all (only the
    # MSVC target has one). /fsanitize=address is incompatible with the /RTC
    # runtime checks CMake's Debug config injects and with incremental linking,
    # so strip /RTC* (globally, which also reaches the library target defined
    # earlier) and force non-incremental linking.
    string(REGEX REPLACE "/RTC[1csu]+" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    string(REGEX REPLACE "/RTC[1csu]+" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

    # The vendored SafetyHook is not instrumented, so the MSVC STL ASan container
    # annotations (annotate_string / annotate_vector / annotate_optional) would
    # differ across the link and fail with LNK2038. Disable those annotations on
    # every instrumented target so all objects agree (value 0); the core ASan
    # checks (heap/stack/use-after-free) stay on. _DISABLE_STL_ANNOTATION is the
    # STL's umbrella switch and auto-defines every per-family disable the toolset
    # knows, so annotation families added in future STL versions stay covered;
    # the explicit string/vector macros remain for VS 2022 toolsets that predate
    # the umbrella. The library is instrumented explicitly because it was created
    # before this block; the tests (added afterwards) pick up the directory options.
    target_compile_options(DetourModKit PRIVATE /fsanitize=address)
    target_compile_definitions(DetourModKit PRIVATE
      _DISABLE_STL_ANNOTATION=1 _DISABLE_STRING_ANNOTATION=1 _DISABLE_VECTOR_ANNOTATION=1)
    add_compile_options(/fsanitize=address)
    add_compile_definitions(_DISABLE_STL_ANNOTATION=1 _DISABLE_STRING_ANNOTATION=1 _DISABLE_VECTOR_ANNOTATION=1)
    add_link_options(/INCREMENTAL:NO)
    message(STATUS "Sanitizers enabled: ASan (MSVC)")
  elseif(WIN32)
    # On Windows only the MSVC toolchain ships the sanitizer runtimes (MSVC
    # AddressSanitizer). A non-MSVC Windows toolchain such as mingw-w64 provides
    # no ASan/UBSan runtime for this target, so -fsanitize would configure
    # cleanly but fail at link or load. Fail fast with a pointer to the supported
    # route rather than letting the user discover it after a long build.
    message(FATAL_ERROR
      "DMK_ENABLE_SANITIZERS on Windows is supported only with the MSVC toolchain "
      "(MSVC AddressSanitizer). The current non-MSVC Windows toolchain (e.g. MinGW) "
      "ships no sanitizer runtime. Reconfigure with MSVC, or leave DMK_ENABLE_SANITIZERS=OFF.")
  else()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "Sanitizers enabled: ASan + UBSan")
  endif()
endif()

# --- Link-Time Optimization ---
# LTO enables cross-translation-unit optimization and dead code elimination in Release builds. Applied per-target to
# avoid inflating build times for external subdirectory targets (SafetyHook, Zydis, Zycore).
include(CheckIPOSupported)
check_ipo_supported(RESULT _ipo_supported LANGUAGES CXX OUTPUT _ipo_error)

# LTO bakes TOOLSET-LOCKED intermediate code into the archive -- MSVC /GL LTCG IL, GCC GIMPLE bytecode -- that the
# CONSUMER's linker must recompile at its own final link. That IL is excluded from MSVC's v140..v143 binary-compatibility
# guarantee, so an installed DetourModKit.lib built with /GL fails a consumer whose Visual Studio toolset differs from
# the one that built it (even a 17.x point update) with C1047 / LNK1257; on GCC it forces every consumer to run a
# matching lto1. A shipped BINARY archive must therefore be plain objects, not IL. An in-tree consumer that pulls DMK in
# via add_subdirectory, by contrast, recompiles it from source with their OWN toolchain, so there is no cross-toolset
# archive to mismatch and LTO is a safe win there. Split the default on exactly that axis: LTO defaults OFF when DMK is
# the top-level project (a standalone build -- what gets installed and packaged, so it must stay portable) and ON when
# DMK is a subproject (add_subdirectory -- recompiled by the consumer, so the lock hazard cannot arise). A consumer can
# override the default explicitly either way.
if(PROJECT_IS_TOP_LEVEL)
  set(_dmk_lto_default OFF)
else()
  set(_dmk_lto_default ON)
endif()
option(DMK_ENABLE_LTO
  "Enable Link-Time Optimization for DetourModKit Release builds. Produces toolset-locked objects, so keep OFF for any archive installed/shipped as a binary; ON is safe only when the consumer recompiles DetourModKit from source."
  ${_dmk_lto_default})

# GCC 15's lto1 has a defect that aborts the consumer's final link with "two or more sections for .gnu.lto_*" on the
# duplicate COMDAT sections of weak template instantiations (std::atomic / std::vector specializations, etc.) pulled from
# an LTO archive. It is not fixable from the consumer side without every consumer passing -fno-lto, and slim vs fat LTO
# objects make no difference (the driver still invokes lto1 on the bytecode). GCC 13.x and MSVC's /GL LTCG are
# unaffected. So even when LTO is explicitly requested, suppress it on the broken GCC major version. Narrow the version
# guard once a fixed GCC 15.x is confirmed upstream.
set(_dmk_lto_broken OFF)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15)
  set(_dmk_lto_broken ON)
endif()

# Resolve the one LTO decision here, once, into a single variable that every target sharing an LTO state reads instead
# of re-spelling the condition. The benchmarks link the DetourModKit archive and must be in the identical LTO state as
# it: a mixed LTO/non-LTO link fails both ways (a non-LTO object against an LTO archive double-emits libstdc++'s
# constrained linkonce symbols; an LTO object against a non-LTO archive is the symmetric hazard). A second,
# independently spelled gate is exactly what drifts -- so the library target and the bench targets both key off
# _dmk_apply_lto rather than each restating "DMK_ENABLE_LTO AND _ipo_supported AND NOT _dmk_lto_broken". Enable only
# when the option is on, the toolchain supports IPO, and the compiler is not a known-broken LTO toolchain.
set(_dmk_apply_lto OFF)
if(DMK_ENABLE_LTO AND _ipo_supported AND NOT _dmk_lto_broken)
  set(_dmk_apply_lto ON)
endif()

if(_dmk_apply_lto)
  set_target_properties(DetourModKit PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
  )
  message(STATUS "LTO enabled for DetourModKit Release builds (DMK_ENABLE_LTO=ON); the resulting archive is toolset-locked")
elseif(DMK_ENABLE_LTO AND _dmk_lto_broken)
  message(STATUS
    "LTO requested (DMK_ENABLE_LTO=ON) but disabled: GCC ${CMAKE_CXX_COMPILER_VERSION} lto1 mis-links LTO static "
    "archives at the consumer's final link; shipping non-LTO objects")
elseif(DMK_ENABLE_LTO)
  message(STATUS "LTO requested (DMK_ENABLE_LTO=ON) but not supported: ${_ipo_error}")
else()
  message(STATUS "LTO disabled (DMK_ENABLE_LTO=OFF); shipping portable, toolset-agnostic objects")
endif()

# --- Unit Tests and Benchmarks ---
# DMK_BUILD_TESTS and DMK_BUILD_BENCHMARKS are declared before the library target because DMK_BUILD_TESTS controls its
# private test-seam definition. DMK_BUILD_BENCHMARKS is the opt-in for the microbenchmark executables (e.g.
# DetourModKit_bench), gated so a normal consumer build produces no extra targets; the bench sources
# live alongside tests/ and are wired up in tests/CMakeLists.txt.
if(DMK_BUILD_TESTS OR DMK_BUILD_BENCHMARKS)
  if(DMK_BUILD_TESTS)
    message(STATUS "Building unit tests...")
    enable_testing()
  endif()

  if(DMK_BUILD_BENCHMARKS)
    message(STATUS "Building benchmarks...")
  endif()

  add_subdirectory(tests)
endif()
