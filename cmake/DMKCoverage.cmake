# dmk_coverage instruments final-link targets and supplies the gcov runtime. The archive is instrumented directly so
# this build-only target never enters its exported interface.

option(DMK_ENABLE_COVERAGE "Enable gcov code-coverage instrumentation (GNU/Clang only)" OFF)

if(NOT TARGET dmk_coverage)
  add_library(dmk_coverage INTERFACE)

  if(DMK_ENABLE_COVERAGE)
    # clang-cl reports Clang but accepts MSVC-style flags, so it cannot consume gcov switches.
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
      target_compile_options(dmk_coverage INTERFACE --coverage)
      target_link_options(dmk_coverage INTERFACE --coverage)
      message(STATUS "Coverage enabled: gcov instrumentation on the DetourModKit archive and every proof that links it")
    else()
      message(STATUS
        "DMK_ENABLE_COVERAGE=ON has no effect on ${CMAKE_CXX_COMPILER_ID}: gcov coverage is GNU/Clang only. "
        "dmk_coverage stays inert.")
    endif()
  endif()
endif()

function(dmk_instrument_for_coverage target)
  if(DMK_ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
    target_compile_options(${target} PRIVATE --coverage)
  endif()
endfunction()
