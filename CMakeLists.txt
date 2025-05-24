cmake_minimum_required(VERSION 3.16)

project(DetourModKit VERSION 1.0.0 LANGUAGES CXX)

# --- Standard and Compiler Options ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BUILD_SHARED_LIBS OFF) # Build DetourModKit as a static library
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Good practice for libraries

# --- Compiler Flags ---
if(MSVC)
  # /W4 for high warning level.
  # Add /WX to treat warnings as errors in CI or for strict builds if desired.
  add_compile_options(/W4)

# Suppress some common noisy MSVC warnings if necessary:
# add_compile_options(/wd4251) # class 'type' needs to have dll-interface...
# add_compile_options(/wd4275) # non dll-interface class 'type' used as base...
else()
  # GCC/Clang specific flags
  add_compile_options(-Wall -Wextra -fexceptions)

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
  add_subdirectory(external/safetyhook) # Process SafetyHook's CMakeLists.txt

  # Define the CMake target name that SafetyHook's build produces for its main library.
  set(SAFETYHOOK_LIBRARY_TARGET_NAME safetyhook) # Common target name, verify if different.
else()
  message(FATAL_ERROR "SafetyHook submodule not found at 'external/safetyhook'. "
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

  PRIVATE

  # For DetourModKit's *own sources* (in src/) to find its *public headers*
  "${CMAKE_CURRENT_SOURCE_DIR}/include"

  # For DetourModKit's own sources to find SimpleIni.h
  "${CMAKE_CURRENT_SOURCE_DIR}/external/simpleini"

  # SafetyHook's public include directories should be propagated transitively
  # by linking with the 'safetyhook' target if SafetyHook's CMakeLists.txt
  # correctly specifies its INTERFACE_INCLUDE_DIRECTORIES.
)

# --- Linking Dependencies for DetourModKit ---
if(TARGET ${SAFETYHOOK_LIBRARY_TARGET_NAME})
  # Link SafetyHook. Zydis and Zycore should be linked transitively if SafetyHook
  # specifies them as PUBLIC or INTERFACE dependencies.
  target_link_libraries(DetourModKit PRIVATE ${SAFETYHOOK_LIBRARY_TARGET_NAME})
  message(STATUS "DetourModKit linked against target: ${SAFETYHOOK_LIBRARY_TARGET_NAME}")
else()
  message(WARNING "SafetyHook library target '${SAFETYHOOK_LIBRARY_TARGET_NAME}' was not found. "
    "DetourModKit may fail to link correctly.")
endif()

# Link necessary system libraries for Windows API calls.
if(WIN32)
  target_link_libraries(DetourModKit PRIVATE
    psapi # Example: for process information functions

    # Add other Windows libraries DetourModKit directly uses, e.g., user32, shell32
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
# This expects your public headers to be in YourProjectRoot/include/DetourModKit/
file(GLOB _dmk_public_headers_for_install
  LIST_DIRECTORIES false
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/DetourModKit/*.hpp"
)

if(_dmk_public_headers_for_install)
  install(FILES ${_dmk_public_headers_for_install}
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/DetourModKit" # Installs to <prefix>/include/DetourModKit
    COMPONENT ${DETOURMODKIT_DEV_COMPONENT}
  )
else()
  message(WARNING "No public headers found in 'include/DetourModKit/*.hpp' to install.")
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
message(STATUS "---------------------------------------------------------------------")
