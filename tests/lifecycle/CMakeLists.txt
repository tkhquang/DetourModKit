# The hung probe is visible only to the outer verifier, so it cannot block the normal suite directly.
add_executable(dmk_timeout_probe timeout_probe.cpp)
dmk_static_runtime(dmk_timeout_probe)

add_test(NAME CTestTimeoutControl
  COMMAND ${CMAKE_COMMAND}
    -DCTEST_EXE=${CMAKE_CTEST_COMMAND}
    -DPROBE=$<TARGET_FILE:dmk_timeout_probe>
    -DSCRATCH=${CMAKE_CURRENT_BINARY_DIR}/timeout_control/$<CONFIG>
    -P ${PROJECT_SOURCE_DIR}/scripts/verify_ctest_timeout.cmake)
set_tests_properties(CTestTimeoutControl PROPERTIES TIMEOUT 120 LABELS "timeout-control")

# Negative control: the verifier must REJECT a nonzero ctest result that is not a timeout. fast_fail_probe exits nonzero
# at once, and the scratch path deliberately contains "timeout", so a verifier matching the bare word rather than the
# "***Timeout" status token would false-pass. WILL_FAIL inverts the verdict, so this proof passes only when the verifier
# FATALs. A larger inner timeout keeps a slow cold launch from turning the fast exit into a real timeout.
add_executable(fast_fail_probe fast_fail_probe.cpp)
dmk_static_runtime(fast_fail_probe)

add_test(NAME CTestTimeoutControlNegative
  COMMAND ${CMAKE_COMMAND}
    -DCTEST_EXE=${CMAKE_CTEST_COMMAND}
    -DPROBE=$<TARGET_FILE:fast_fail_probe>
    -DSCRATCH=${CMAKE_CURRENT_BINARY_DIR}/timeout_control_neg/$<CONFIG>
    -DINNER_TIMEOUT=60
    -P ${PROJECT_SOURCE_DIR}/scripts/verify_ctest_timeout.cmake)
set_tests_properties(CTestTimeoutControlNegative PROPERTIES WILL_FAIL TRUE TIMEOUT 120 LABELS "timeout-control")

# Static-destruction order is a language guarantee, not loader behavior, so this proof runs on both toolchains rather
# than inside the MinGW-specific loader gate below.
add_executable(hook_static_order test_hook_static_order.cpp)
target_link_libraries(hook_static_order PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(hook_static_order PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
dmk_static_runtime(hook_static_order)

dmk_add_raw_proof(NAME Lifecycle.StaticHookCannotOutliveLedgerState
  COMMAND $<TARGET_FILE:hook_static_order>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:hook_static_order>
  LABELS "lifecycle-proof")

# These proofs exercise MinGW runtime behavior; MSVC-specific loader proofs require separate fixtures.
if(MINGW)
  # The probe DLL links coverage because it consumes the instrumented archive.
  add_library(bootstrap_probe SHARED bootstrap_probe_dll.cpp)
  set_target_properties(bootstrap_probe PROPERTIES PREFIX "" OUTPUT_NAME "bootstrap_probe")
  target_link_libraries(bootstrap_probe PRIVATE DetourModKit dmk_coverage psapi dbghelp ntdll)
  target_include_directories(bootstrap_probe PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src)
  dmk_static_runtime(bootstrap_probe SHARED)

  # The loader host and its companion DLL share an output directory so bare-name loading is deterministic.
  add_executable(bootstrap_module_ref test_bootstrap_module_ref.cpp)
  add_dependencies(bootstrap_module_ref bootstrap_probe)
  dmk_static_runtime(bootstrap_module_ref)

  # Compiling profiler.cpp directly lets the poisoning allocator govern its ring. Coverage is excluded because gcov
  # may allocate during process teardown.
  add_executable(profiler_late_uaf
    test_profiler_late_uaf.cpp
    ${PROJECT_SOURCE_DIR}/src/profiler.cpp)
  target_include_directories(profiler_late_uaf PRIVATE ${PROJECT_SOURCE_DIR}/include)
  dmk_static_runtime(profiler_late_uaf)

  dmk_add_raw_proof(NAME Lifecycle.BootstrapWorkerStaysMapped
    COMMAND $<TARGET_FILE:bootstrap_module_ref> mapped
    WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
    LABELS "lifecycle-proof")
  dmk_add_raw_proof(NAME Lifecycle.BootstrapWorkerDrainedUnloads
    COMMAND $<TARGET_FILE:bootstrap_module_ref> unload
    WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
    LABELS "lifecycle-proof")
  dmk_add_raw_proof(NAME Lifecycle.ProfilerLateScopedProfileNoUAF
    COMMAND $<TARGET_FILE:profiler_late_uaf>
    WORKING_DIRECTORY $<TARGET_FILE_DIR:profiler_late_uaf>
    LABELS "lifecycle-proof")
endif()
