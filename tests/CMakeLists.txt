cmake_minimum_required(VERSION 3.16)

# Enable testing
enable_testing()

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

# Enable testing for the DetourModKit library
add_executable(DetourModKit_tests
  main.cpp
  test_logger.cpp
  test_async_logger.cpp
  test_config.cpp
  test_format_utils.cpp
  test_string_utils.cpp
  test_math_utils.cpp
  test_memory_utils.cpp
  test_aob_scanner.cpp
  test_hook_manager.cpp
  test_filesystem_utils.cpp
)

# Link GoogleTest and DetourModKit
target_link_libraries(DetourModKit_tests
  PRIVATE
  DetourModKit
  GTest::gtest_main
)

# Include directories
target_include_directories(DetourModKit_tests PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/external/simpleini
  ${DIRECTXMATH_INCLUDE_DIR}
)

# Register tests with CTest
include(GoogleTest)
gtest_discover_tests(DetourModKit_tests)

# Optional: Add code coverage if requested
option(DMK_ENABLE_COVERAGE "Enable code coverage reporting" OFF)

if(DMK_ENABLE_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(DetourModKit_tests PRIVATE --coverage -fprofile-arcs -ftest-coverage)
    target_link_options(DetourModKit_tests PRIVATE --coverage)
  endif()
endif()
