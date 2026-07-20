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

# First-use logger state is allocation/language behavior, not loader behavior, so these cases run on both toolchains.
# The driver replaces plain global operator new for its single- and concurrent-OOM modes and also supplies a successful
# control. It links the archive so log()'s real construction path is exercised end to end; exit status is the oracle.
add_executable(logger_first_use_oom logger_first_use_oom.cpp)
target_link_libraries(logger_first_use_oom PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(logger_first_use_oom PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(logger_first_use_oom)

dmk_add_raw_proof(NAME Lifecycle.LoggerFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:logger_first_use_oom> oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_first_use_oom>
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.LoggerConcurrentFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:logger_first_use_oom> concurrent-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_first_use_oom>
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.LoggerFirstUseSuccessCreatesLiveSink
  COMMAND $<TARGET_FILE:logger_first_use_oom> success
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_first_use_oom>
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

# The reload servicer's reaper self-retirement (a config setter on the servicer thread calling clear()) is language and
# threading behavior, not loader behavior, so it runs on both toolchains. A self-join regression wedges the servicer
# worker forever, which the standalone process and its ctest timeout catch.
add_executable(config_servicer_self_retire test_config_servicer_self_retire.cpp)
target_link_libraries(config_servicer_self_retire PRIVATE DetourModKit dmk_coverage)
target_include_directories(config_servicer_self_retire PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
dmk_static_runtime(config_servicer_self_retire)

dmk_add_raw_proof(NAME Lifecycle.ReloadServicerSelfRetiresThroughReaper
  COMMAND $<TARGET_FILE:config_servicer_self_retire>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:config_servicer_self_retire>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# A binding callback that calls Input::shutdown() makes the poll thread its own teardown thread. The regression is a
# self-join raised out of a noexcept function, which terminates the process rather than failing an assertion, so the
# proof needs its own process and exit status as the oracle. Language and threading behavior: both toolchains.
add_executable(input_self_shutdown input_self_shutdown.cpp)
target_link_libraries(input_self_shutdown PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(input_self_shutdown PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(input_self_shutdown PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(input_self_shutdown)

dmk_add_raw_proof(NAME Lifecycle.InputCallbackSelfShutdownDoesNotJoinSelf
  COMMAND $<TARGET_FILE:input_self_shutdown> self-shutdown
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_self_shutdown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.InputRegistrationRacesCallbackShutdown
  COMMAND $<TARGET_FILE:input_self_shutdown> registration-race
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_self_shutdown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.InputExternalShutdownRunsDownSynchronously
  COMMAND $<TARGET_FILE:input_self_shutdown> external-shutdown
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_self_shutdown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# First-use singleton state is allocation and language behavior, so these run on both toolchains. The driver replaces
# plain global operator new for its single- and concurrent-OOM modes and supplies a successful control.
add_executable(input_first_use_oom input_first_use_oom.cpp)
target_link_libraries(input_first_use_oom PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(input_first_use_oom PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(input_first_use_oom)

dmk_add_raw_proof(NAME Lifecycle.InputFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:input_first_use_oom> oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_first_use_oom>
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.InputConcurrentFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:input_first_use_oom> concurrent-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_first_use_oom>
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.InputFirstUseSuccessStartsEngine
  COMMAND $<TARGET_FILE:input_first_use_oom> success
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_first_use_oom>
  LABELS "lifecycle-proof")

# The XInput timeout branch latches a process-lifetime permanent detour, so it cannot share a process with the ordinary
# install/uninstall cases in the unit binary. The keepalive-balance case needs a process whose only reference on the
# patched module is its own.
add_executable(xinput_detour_rundown xinput_detour_rundown.cpp)
target_link_libraries(xinput_detour_rundown PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(xinput_detour_rundown PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(xinput_detour_rundown PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(xinput_detour_rundown)

dmk_add_raw_proof(NAME Lifecycle.XInputTimeoutRetainsTrampolinesWithoutAllocating
  COMMAND $<TARGET_FILE:xinput_detour_rundown> timeout
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputDrainedTeardownBalancesModuleReferences
  COMMAND $<TARGET_FILE:xinput_detour_rundown> reference-balance
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
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
