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

# Two DLLs from one source, each linking the DetourModKit archive, give one process two independent kits. That is the
# only configuration in which the per-linked-instance ledger scope is observable, so it runs on both toolchains: the
# scope follows from static linkage, not from loader behavior.
foreach(kit kit_a kit_b)
  add_library(${kit} SHARED hook_kit_dll.cpp)
  set_target_properties(${kit} PROPERTIES PREFIX "" OUTPUT_NAME "${kit}")
  # The kit performs the final link of the instrumented archive, so it needs the coverage runtime.
  target_link_libraries(${kit} PRIVATE DetourModKit dmk_coverage)
  target_include_directories(${kit} PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src)
  dmk_static_runtime(${kit} SHARED)
endforeach()

# The host only needs the ErrorCode enum, so it does not link the archive; it must not carry a third kit of its own.
add_executable(hook_instance_scope test_hook_instance_scope.cpp)
target_include_directories(hook_instance_scope PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_dependencies(hook_instance_scope kit_a kit_b hook_target_lib)
dmk_static_runtime(hook_instance_scope)

# The host loads its DLLs by bare name, which resolves from the application directory. The kits build into that
# directory already; hook_target_lib is declared one level up and has to be staged in.
add_custom_command(TARGET hook_instance_scope POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:hook_target_lib>
    $<TARGET_FILE_DIR:hook_instance_scope>)

# Each scenario is its own process so none inherits another's patches. The ctest name states the claim proved; the argv
# token stays the scenario keyword the host dispatches on.
set(hook_instance_scope_proofs
  Lifecycle.HookLedgerIsPerLinkedInstance          distinct
  Lifecycle.HookLedgerRefusesSameKitDuplicate      same-kit
  Lifecycle.HookLedgerIsBlindAcrossLinkedInstances cross-kit
  Lifecycle.ArmedForeignHookIsRefusedByDecode      armed)
while(hook_instance_scope_proofs)
  list(POP_FRONT hook_instance_scope_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:hook_instance_scope> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:hook_instance_scope>
    LABELS "lifecycle-proof")
endwhile()

# A deadlock needs an isolated process so its timeout cannot wedge the shared unit binary.
add_executable(input_gate_abba test_input_gate_abba.cpp)
target_link_libraries(input_gate_abba PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(input_gate_abba PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(input_gate_abba PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(input_gate_abba)

dmk_add_raw_proof(NAME Lifecycle.CrossBindingReleaseHasNoABBA
  COMMAND $<TARGET_FILE:input_gate_abba>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 60
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
