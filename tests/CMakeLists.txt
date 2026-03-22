cmake_minimum_required(VERSION 3.25)

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Suppress warnings from GoogleTest sources
foreach(_ext_target gtest gtest_main gmock gmock_main)
  if(TARGET ${_ext_target})
    target_compile_options(${_ext_target} PRIVATE
      $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-w>
      $<$<CXX_COMPILER_ID:MSVC>:/w>
    )
  endif()
endforeach()

# Test fixture DLL for cross-module hook integration tests
add_library(hook_target_lib SHARED
  "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hook_target_lib.cpp"
)
set_target_properties(hook_target_lib PROPERTIES
  PREFIX ""
  OUTPUT_NAME "hook_target_lib"
)

# Automatically collect all test source files
# This will include all test_*.cpp files and main.cpp
file(GLOB TEST_SOURCES
  CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
)

# Sort the list for deterministic build order
list(SORT TEST_SOURCES)

message(STATUS "Discovered test files:")

foreach(test_file ${TEST_SOURCES})
  message(STATUS "  - ${test_file}")
endforeach()

# Enable testing for the DetourModKit library
add_executable(DetourModKit_tests ${TEST_SOURCES})

# Ensure the hook target DLL is built before tests and placed alongside the test exe
add_dependencies(DetourModKit_tests hook_target_lib)
add_custom_command(TARGET hook_target_lib POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:hook_target_lib>
    $<TARGET_FILE_DIR:DetourModKit_tests>
)

# Link GoogleTest and DetourModKit.
# psapi is needed by test_hook_integration.cpp (GetModuleInformation).
# user32 and xinput1_4 propagate transitively from DetourModKit (INTERFACE).
target_link_libraries(DetourModKit_tests
  PRIVATE
  DetourModKit
  GTest::gtest_main
  psapi
  user32
)

# Include directories
target_include_directories(DetourModKit_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/include
)

# External dependency headers as SYSTEM to suppress their warnings
target_include_directories(DetourModKit_tests SYSTEM PRIVATE
  ${CMAKE_SOURCE_DIR}/external/simpleini
  ${DIRECTXMATH_INCLUDE_DIR}
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(DetourModKit_tests DISCOVERY_MODE PRE_TEST)

# Optional: Add code coverage if requested
option(DMK_ENABLE_COVERAGE "Enable code coverage reporting" OFF)

if(DMK_ENABLE_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Instrument both the library and the test executable for coverage
    target_compile_options(DetourModKit PRIVATE --coverage -fprofile-arcs -ftest-coverage)
    target_link_options(DetourModKit PRIVATE --coverage)
    target_compile_options(DetourModKit_tests PRIVATE --coverage -fprofile-arcs -ftest-coverage)
    target_link_options(DetourModKit_tests PRIVATE --coverage)
  endif()
endif()
