# TIMEOUT bounds case execution; DISCOVERY_TIMEOUT only bounds GoogleTest enumeration.
set(DMK_TEST_TIMEOUT_SECONDS "300" CACHE STRING
  "Per-case CTest execution TIMEOUT for DetourModKit proofs, in seconds")

# Cold discovery of the large static Debug binary can exceed CTest's five-second default.
set(DMK_DISCOVERY_TIMEOUT_SECONDS "120" CACHE STRING
  "GoogleTest PRE_TEST discovery timeout for DetourModKit proofs, in seconds")

# Static MinGW executables avoid resolving a mismatched runtime during PRE_TEST discovery. DLLs can embed only the
# gcc and standard-library runtimes.
function(dmk_static_runtime target)
  cmake_parse_arguments(_R "SHARED" "" "" ${ARGN})
  if(MINGW)
    if(_R_SHARED)
      target_link_options(${target} PRIVATE -static-libgcc -static-libstdc++)
    else()
      target_link_options(${target} PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
  endif()
endfunction()

#   dmk_add_gtest_proof(
#     TARGET <name> SOURCES <a.cpp...>
#     [LINK <lib...>] [INCLUDE <dir...>] [SYSTEM_INCLUDE <dir...>] [DEFINES <def...>]
#     [DEPENDS <target...>] [LABELS <label...>]
#     [DISCOVERY_TIMEOUT <s>] [TEST_TIMEOUT <s>])
function(dmk_add_gtest_proof)
  cmake_parse_arguments(P "" "TARGET;DISCOVERY_TIMEOUT;TEST_TIMEOUT"
    "SOURCES;LINK;INCLUDE;SYSTEM_INCLUDE;DEFINES;DEPENDS;LABELS" ${ARGN})

  if(NOT P_TARGET OR NOT P_SOURCES)
    message(FATAL_ERROR "dmk_add_gtest_proof requires TARGET and SOURCES")
  endif()

  add_executable(${P_TARGET} ${P_SOURCES})
  target_link_libraries(${P_TARGET} PRIVATE DetourModKit GTest::gtest_main dmk_coverage ${P_LINK})

  if(P_INCLUDE)
    target_include_directories(${P_TARGET} PRIVATE ${P_INCLUDE})
  endif()

  if(P_SYSTEM_INCLUDE)
    target_include_directories(${P_TARGET} SYSTEM PRIVATE ${P_SYSTEM_INCLUDE})
  endif()

  target_compile_definitions(${P_TARGET} PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS> ${P_DEFINES})

  dmk_static_runtime(${P_TARGET})

  foreach(_dep IN LISTS P_DEPENDS)
    add_dependencies(${P_TARGET} ${_dep})
  endforeach()

  if(NOT P_DISCOVERY_TIMEOUT)
    set(P_DISCOVERY_TIMEOUT ${DMK_DISCOVERY_TIMEOUT_SECONDS})
  endif()

  if(NOT P_TEST_TIMEOUT)
    set(P_TEST_TIMEOUT ${DMK_TEST_TIMEOUT_SECONDS})
  endif()

  set(_props TIMEOUT ${P_TEST_TIMEOUT})
  if(P_LABELS)
    list(APPEND _props LABELS "${P_LABELS}")
  endif()

  include(GoogleTest)
  gtest_discover_tests(${P_TARGET}
    DISCOVERY_MODE PRE_TEST
    DISCOVERY_TIMEOUT ${P_DISCOVERY_TIMEOUT}
    PROPERTIES ${_props})
endfunction()

#   dmk_add_raw_proof(NAME <ctest-name> COMMAND <cmd...>
#     [WORKING_DIRECTORY <dir>] [LABELS <label...>] [TEST_TIMEOUT <s>])
function(dmk_add_raw_proof)
  cmake_parse_arguments(P "" "NAME;WORKING_DIRECTORY;TEST_TIMEOUT" "COMMAND;LABELS" ${ARGN})

  if(NOT P_NAME OR NOT P_COMMAND)
    message(FATAL_ERROR "dmk_add_raw_proof requires NAME and COMMAND")
  endif()

  if(NOT P_TEST_TIMEOUT)
    set(P_TEST_TIMEOUT ${DMK_TEST_TIMEOUT_SECONDS})
  endif()

  add_test(NAME ${P_NAME} COMMAND ${P_COMMAND})

  set(_props TIMEOUT ${P_TEST_TIMEOUT})
  if(P_WORKING_DIRECTORY)
    list(APPEND _props WORKING_DIRECTORY "${P_WORKING_DIRECTORY}")
  endif()
  if(P_LABELS)
    list(APPEND _props LABELS "${P_LABELS}")
  endif()
  set_tests_properties(${P_NAME} PROPERTIES ${_props})
endfunction()
