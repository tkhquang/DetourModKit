cmake_minimum_required(VERSION 3.25)

project(DetourModKit VERSION 2.3.0 LANGUAGES CXX)

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

if(MSVC)
  add_compile_options(/W4)
  if(DMK_WARNINGS_AS_ERRORS)
    add_compile_options(/WX)
  endif()

  # Security hardening: ASLR, DEP, and Control Flow Guard
  add_link_options(/DYNAMICBASE /NXCOMPAT /GUARD:CF)
  add_compile_options(/guard:cf)

  # Debug builds: embed CodeView debug info directly into .obj files (/Z7)
  # to avoid PDB file locking issues during parallel builds.
  # Release builds: no debug info to minimize binary size.
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
    "$<$<CONFIG:Debug>:Embedded>$<$<NOT:$<CONFIG:Debug>>:>")
  set(CMAKE_COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pdb")

# Suppress noisy MSVC warnings:
# add_compile_options(/wd4324) # suppressed at source in async_logger.hpp
# add_compile_options(/wd4251) # class 'type' needs to have dll-interface...
# add_compile_options(/wd4275) # non dll-interface class 'type' used as base...
else()
  # GCC/Clang specific flags
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
  if(DMK_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
  endif()

  # Security hardening: ASLR and DEP (NX) for MinGW targets
  add_link_options(-Wl,--dynamicbase -Wl,--nxcompat)

  # Override CMake's default -O3 for Release with -O2.
  # -O2 provides a better code-size/performance tradeoff; the scanner's
  # SSE2 intrinsics are already hand-optimized and do not benefit from
  # -O3's aggressive loop unrolling and auto-vectorization.
  string(REPLACE "-O3" "-O2" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
  string(REPLACE "-O3" "-O2" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

  # Suppress specific GCC/Clang warnings if they are noisy or from dependencies
  # add_compile_options(-Wno-unused-parameter -Wno-missing-field-initializers)
endif()

# --- Dependencies ---
# SimpleIni will be added as an include directory directly to the DetourModKit target.

# SafetyHook (built from submodule using add_subdirectory)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/safetyhook/CMakeLists.txt")
  message(STATUS "Configuring SafetyHook from submodule: external/safetyhook")

  # Set options for SafetyHook's CMake build BEFORE calling add_subdirectory.
  set(SAFETYHOOK_FETCH_ZYDIS ON CACHE BOOL "Let SafetyHook manage fetching and building Zydis" FORCE)
  set(SAFETYHOOK_BUILD_TESTS OFF CACHE BOOL "Disable building SafetyHook's internal tests" FORCE)
  set(SAFETYHOOK_BUILD_EXAMPLES OFF CACHE BOOL "Disable building SafetyHook's examples" FORCE)

  # SafetyHook and its dependencies (Zydis, Zycore) should also be built as static libraries.
  # Setting BUILD_SHARED_LIBS to OFF globally (done above) should influence this for
  # well-behaved CMake subprojects. Explicit definitions below will reinforce this.
  add_subdirectory(external/safetyhook SYSTEM) # SYSTEM suppresses compiler warnings from external headers

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
  set(SAFETYHOOK_LIBRARY_TARGET_NAME safetyhook) # Common target name, verify if different.
else()
  message(FATAL_ERROR "SafetyHook submodule not found at 'external/safetyhook'. "
    "Please ensure submodules are initialized and updated: "
    "'git submodule update --init --recursive'")
endif()

# DirectXMath (header-only library from submodule)
set(DIRECTXMATH_INCLUDE_DIR "")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/DirectXMath/Inc/DirectXMath.h")
  set(DIRECTXMATH_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/DirectXMath/Inc")
  message(STATUS "DirectXMath found at: ${DIRECTXMATH_INCLUDE_DIR}")
else()
  message(FATAL_ERROR "DirectXMath submodule not found at 'external/DirectXMath'. "
    "Please ensure submodules are initialized and updated: "
    "'git submodule update --init --recursive'")
endif()

# --- Compile Definitions for DetourModKit and potentially for headers it includes ---
if(WIN32)
  add_compile_definitions(
    WINVER=0x0A00 # Target Windows 10 or later
    _WIN32_WINNT=0x0A00 # Target Windows 10 or later
  )
endif()

# Definitions for static linking against SafetyHook and Zydis/Zycore.
# These are important if headers from these libraries use these macros.
add_compile_definitions(
  SAFETYHOOK_NO_DLL # Often used by libraries to adjust for static vs. shared builds
  ZYDIS_STATIC_BUILD # Recommended by Zydis docs for static linking
  ZYCORE_STATIC_BUILD # Assuming Zycore follows a similar pattern
)

# --- DetourModKit Library Target Definition ---
# Glob source files. CONFIGURE_DEPENDS helps CMake re-glob on CMakeLists changes.
# For brand new files, a manual CMake re-run might still be needed.
file(GLOB DETOURMODKIT_SOURCE_FILES
  CONFIGURE_DEPENDS
  "src/*.cpp"
)

if(NOT DETOURMODKIT_SOURCE_FILES)
  message(WARNING "No C++ source files found in 'src/*.cpp' for the DetourModKit library. "
    "The library will be built empty if no sources are listed.")
else()
  # message(STATUS "DetourModKit sources: ${DETOURMODKIT_SOURCE_FILES}") # Uncomment for debugging
endif()

# Define the DetourModKit static library target
add_library(DetourModKit STATIC
  ${DETOURMODKIT_SOURCE_FILES}
)

# NOMINMAX applied only to DetourModKit (not globally) to avoid
# redefinition warnings in external dependencies like SafetyHook
if(WIN32)
  target_compile_definitions(DetourModKit PUBLIC NOMINMAX)
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
endif()

# Set output name and prefix properties for consistency
# For most generators (like MinGW Makefiles), PREFIX is "lib" by default for static/shared libs.
# For MSVC, PREFIX is empty by default for static/shared libs.
# We want the output file to be "libDetourModKit.lib" on MSVC.
# And "libDetourModKit.a" on MinGW (which is the default).
set_target_properties(DetourModKit PROPERTIES
  OUTPUT_NAME "DetourModKit"
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
  $<INSTALL_INTERFACE:include>

  # For consumers using DetourModKit as a subdirectory (BUILD_INTERFACE):
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>

  # DirectXMath headers for both build and install interfaces
  $<BUILD_INTERFACE:${DIRECTXMATH_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/DirectXMath>

  PRIVATE

  # For DetourModKit's *own sources* (in src/) to find its *public headers*
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# External dependency headers marked as SYSTEM to suppress their warnings
target_include_directories(DetourModKit SYSTEM
  PUBLIC
  $<BUILD_INTERFACE:${DIRECTXMATH_INCLUDE_DIR}>

  PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/external/simpleini"
  "${DIRECTXMATH_INCLUDE_DIR}"
)

# --- Linking Dependencies for DetourModKit ---
if(TARGET ${SAFETYHOOK_LIBRARY_TARGET_NAME})
  # Link SafetyHook. Zydis and Zycore should be linked transitively if SafetyHook
  # specifies them as PUBLIC or INTERFACE dependencies.
  target_link_libraries(DetourModKit PUBLIC ${SAFETYHOOK_LIBRARY_TARGET_NAME})
  message(STATUS "DetourModKit linked against target: ${SAFETYHOOK_LIBRARY_TARGET_NAME}")
else()
  message(WARNING "SafetyHook library target '${SAFETYHOOK_LIBRARY_TARGET_NAME}' was not found. "
    "DetourModKit may fail to link correctly.")
endif()

# Link necessary system libraries for Windows API calls.
# INTERFACE so consumers of this static library automatically resolve these
# import libraries when linking the final DLL/EXE.
# The XInput import library name differs between toolchains:
#   MSVC / Windows SDK: xinput.lib  (links against xinput1_4.dll at runtime)
#   MinGW:              -lxinput1_4 (libxinput1_4.a ships with mingw-w64)
if(WIN32)
  if(MSVC)
    set(_DMK_XINPUT_LIB xinput)
  else()
    set(_DMK_XINPUT_LIB xinput1_4)
  endif()

  target_link_libraries(DetourModKit INTERFACE
    user32          # GetAsyncKeyState, GetForegroundWindow, GetWindowThreadProcessId
    ${_DMK_XINPUT_LIB} # XInput gamepad polling (xinput1_4.dll ships with Win8+)
  )
endif()

# --- Installation Rules ---
# Define common install component names for clarity and potential partial installs.
set(DETOURMODKIT_LIB_COMPONENT lib) # For the library files (.a, .lib)
set(DETOURMODKIT_DEV_COMPONENT dev) # For development files (headers, CMake config)
set(DETOURMODKIT_DOCS_COMPONENT docs) # For documentation (LICENSE, README)

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

# Install the centralized DetourModKit.hpp header
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit.hpp")
  install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
  )
  message(STATUS "Centralized DetourModKit.hpp header will be installed.")
else()
  message(WARNING "Centralized header 'include/DetourModKit.hpp' not found.")
endif()

# Install DirectXMath headers
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

# --- CMake Package Configuration for Consumers ---
include(CMakePackageConfigHelpers) # Provides helper macros
include(GNUInstallDirs) # Provides standard CMAKE_INSTALL_*DIR variables

# Define a variable for the CMake package configuration install directory.
# Common locations are lib/cmake/<PackageName> or share/cmake/<PackageName>.
set(DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/DetourModKit")

# Create DetourModKitConfigVersion.cmake (records the version of the installed package)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion # Consumers can use this or newer compatible versions
)

# Create DetourModKitTargets.cmake for the *installed* package.
# This file allows CMake to import the DetourModKit library target when found by find_package.
install(EXPORT DetourModKitTargets
  FILE DetourModKitTargets.cmake # Name of the file to be generated and installed
  NAMESPACE DetourModKit:: # Namespace for imported targets (e.g., DetourModKit::DetourModKit)
  DESTINATION "${DETOURMODKIT_CMAKE_CONFIG_INSTALL_DIR}"
  COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
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

# Install the configured DetourModKitConfig.cmake and the version file.
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/DetourModKitConfigVersion.cmake"
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

# --- Sanitizers ---
option(DMK_ENABLE_SANITIZERS "Enable ASan and UBSan (GCC/Clang only)" OFF)

if(DMK_ENABLE_SANITIZERS AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
  message(STATUS "Sanitizers enabled: ASan + UBSan")
endif()

# --- Link-Time Optimization ---
# LTO enables cross-translation-unit optimization and dead code elimination
# in Release builds. Applied per-target to avoid inflating build times for
# external subdirectory targets (SafetyHook, Zydis, Zycore).
include(CheckIPOSupported)
check_ipo_supported(RESULT _ipo_supported LANGUAGES CXX OUTPUT _ipo_error)

if(_ipo_supported)
  set_target_properties(DetourModKit PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
  )
  message(STATUS "LTO enabled for DetourModKit Release builds")
else()
  message(STATUS "LTO not supported: ${_ipo_error}")
endif()

# --- Unit Tests ---
option(DMK_BUILD_TESTS "Build unit tests" OFF)

if(DMK_BUILD_TESTS)
  message(STATUS "Building unit tests...")
  enable_testing()
  add_subdirectory(tests)
endif()
