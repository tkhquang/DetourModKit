# This target isolates persistent PAGE_NOACCESS fixtures from the monolithic suite. It is MinGW-only because these
# cases exercise the vectored-exception-handler implementation.
if(MINGW)
  file(GLOB DMK_FAULT_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp")

  if(DMK_FAULT_SOURCES)
    dmk_add_gtest_proof(
      TARGET fault_tests
      SOURCES ${DMK_FAULT_SOURCES}
      LINK psapi dbghelp ntdll
      INCLUDE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/tests/fixtures
      SYSTEM_INCLUDE
        ${PROJECT_SOURCE_DIR}/external/simpleini
        ${DIRECTXMATH_INCLUDE_DIR}
      LABELS "fault-proof")
  else()
    message(STATUS "No tests/fault/test_*.cpp sources found; the fault-containment proof target is not registered.")
  endif()
endif()
