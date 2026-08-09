# Persistent PAGE_NOACCESS fixtures, isolated from the monolithic suite. Both toolchains register every case: the
# cases carry their own per-compiler arms where the fault frame differs (MSVC __try/__except versus the MinGW vectored
# handler), so a gate here would leave MSVC's SEH paths unproven rather than avoiding a wrong expectation.
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

# An access violation that must NOT be contained cannot share a process with anything else, and the verdict is which
# frame claimed it, which no in-process assertion can read. The host drives the real scanners through the
# DMK_ENABLE_TEST_SEAMS-gated injection point and reports the answer as its exit status.
add_executable(fault_scanner_escape_probe fault_scanner_escape_probe.cpp)
target_link_libraries(fault_scanner_escape_probe PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(fault_scanner_escape_probe PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src
  ${PROJECT_SOURCE_DIR}/tests/fixtures)
target_compile_definitions(fault_scanner_escape_probe PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(fault_scanner_escape_probe)

dmk_add_raw_proof(NAME FaultProof.RegionSweepDoesNotSwallowAnOutOfSpanFault
  COMMAND $<TARGET_FILE:fault_scanner_escape_probe> region
  WORKING_DIRECTORY $<TARGET_FILE_DIR:fault_scanner_escape_probe>
  TEST_TIMEOUT 60
  LABELS "fault-proof")

dmk_add_raw_proof(NAME FaultProof.NarrowWindowSweepDoesNotSwallowAnOutOfSpanFault
  COMMAND $<TARGET_FILE:fault_scanner_escape_probe> xref
  WORKING_DIRECTORY $<TARGET_FILE_DIR:fault_scanner_escape_probe>
  TEST_TIMEOUT 60
  LABELS "fault-proof")

dmk_add_raw_proof(NAME FaultProof.NarrowWindowSweepContainsAnInSpanFault
  COMMAND $<TARGET_FILE:fault_scanner_escape_probe> xref-in-span
  WORKING_DIRECTORY $<TARGET_FILE_DIR:fault_scanner_escape_probe>
  TEST_TIMEOUT 60
  LABELS "fault-proof")

# Negative control. The scenarios above select on argv[1] in one host, so a typo'd token -- or a host built before a
# scenario existed -- would otherwise run some other path and report PASS having asserted nothing about what it names.
# WILL_FAIL inverts the verdict, so this passes only while the host rejects a token it does not implement.
add_test(NAME FaultProof.ScannerEscapeProbeRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:fault_scanner_escape_probe> no-such-scenario)
set_tests_properties(FaultProof.ScannerEscapeProbeRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:fault_scanner_escape_probe>
  LABELS "fault-proof")
