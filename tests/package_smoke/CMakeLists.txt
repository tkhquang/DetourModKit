cmake_minimum_required(VERSION 3.25)

project(DetourModKitPackageSmoke LANGUAGES CXX)

# Intentionally do NOT set CMAKE_CXX_STANDARD here. The installed DetourModKit target carries cxx_std_23 as a
# PUBLIC compile feature, so linking DetourModKit::DetourModKit must raise this consumer to C++23 on its own.
# Setting the standard locally would mask a regression where that requirement stopped being exported.

find_package(DetourModKit REQUIRED)

# The installed package must expose every non-optional ABI fact recorded by its producing configure.
foreach(_dmk_abi_axis
    COMPILER_ID
    COMPILER_VERSION
    STL
    CXX_STANDARD
    ITERATOR_DEBUG_LEVEL
    ARCHITECTURE
    POINTER_SIZE
    BUILD_TYPE)
  if(NOT DEFINED DetourModKit_ABI_${_dmk_abi_axis} OR "${DetourModKit_ABI_${_dmk_abi_axis}}" STREQUAL "")
    message(FATAL_ERROR "DetourModKit package omitted ABI axis ${_dmk_abi_axis}")
  endif()
endforeach()
if(NOT DetourModKit_ABI_CXX_STANDARD STREQUAL "23")
  message(FATAL_ERROR "DetourModKit package recorded an unexpected C++ standard")
endif()

# windows_macro_probe.cpp proves every public header compiles after <windows.h> without NOMINMAX (on MSVC
# that includes the live min/max macros); main.cpp additionally asserts backend and macro absence at compile time.
add_executable(dmk_package_smoke main.cpp windows_macro_probe.cpp)
target_link_libraries(dmk_package_smoke PRIVATE DetourModKit::DetourModKit)

# Statically link the GCC runtime on MinGW. This is a CI-runner workaround, not a consumer recommendation: a
# Windows runner can resolve a mismatched libstdc++ / libgcc / libwinpthread on PATH instead of the runtime from the
# toolchain that built the executable, which makes the smoke binary hang at startup/teardown. Embedding the runtime
# makes the installed-package check PATH-independent without changing what is verified: find_package wiring and the
# exported C++23 requirement.
if(MINGW)
  target_link_options(dmk_package_smoke PRIVATE -static -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_test(NAME dmk_package_smoke COMMAND dmk_package_smoke)
