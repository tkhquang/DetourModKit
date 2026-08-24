# The single build-target owner for this directory's proof hosts. A registered ctest declares no build dependency on
# its host, so CI and scripts/run_lifecycle_proofs.sh build this aggregate instead of naming hosts. Register each
# host on it beside the host's declaration. Lifecycle.LabelInventoryIsComplete rejects a lost case.
add_custom_target(dmk_lifecycle_proof_hosts)

# The hung probe is visible only to the outer verifier, so it cannot block the normal suite directly.
add_executable(dmk_timeout_probe timeout_probe.cpp)
dmk_static_runtime(dmk_timeout_probe)
add_dependencies(dmk_lifecycle_proof_hosts dmk_timeout_probe)

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
add_dependencies(dmk_lifecycle_proof_hosts fast_fail_probe)

add_test(NAME CTestTimeoutControlNegative
  COMMAND ${CMAKE_COMMAND}
    -DCTEST_EXE=${CMAKE_CTEST_COMMAND}
    -DPROBE=$<TARGET_FILE:fast_fail_probe>
    -DSCRATCH=${CMAKE_CURRENT_BINARY_DIR}/timeout_control_neg/$<CONFIG>
    -DINNER_TIMEOUT=60
    -P ${PROJECT_SOURCE_DIR}/scripts/verify_ctest_timeout.cmake)
set_tests_properties(CTestTimeoutControlNegative PROPERTIES WILL_FAIL TRUE TIMEOUT 120 LABELS "timeout-control")

# Static-destruction order is a language guarantee, not loader behavior, so this proof runs on both toolchains.
add_executable(hook_static_order test_hook_static_order.cpp)
target_link_libraries(hook_static_order PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(hook_static_order PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(hook_static_order PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(hook_static_order)
add_dependencies(dmk_lifecycle_proof_hosts hook_static_order)

dmk_add_raw_proof(NAME Lifecycle.StaticHookCannotOutliveLedgerState
  COMMAND $<TARGET_FILE:hook_static_order>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:hook_static_order>
  LABELS "lifecycle-proof")

# Main constructs the process VMT object gate after the namespace-scope owner.
# C++ defines their reverse destruction order, so this proof runs on both toolchains.
add_executable(vmt_late_static_owner vmt_late_static_owner.cpp)
target_link_libraries(vmt_late_static_owner PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(vmt_late_static_owner PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(vmt_late_static_owner PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(vmt_late_static_owner)
add_dependencies(dmk_lifecycle_proof_hosts vmt_late_static_owner)

dmk_add_raw_proof(NAME Lifecycle.LateVmtOwnerOutlivesTheObjectGate
  COMMAND $<TARGET_FILE:vmt_late_static_owner>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:vmt_late_static_owner>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# Deliberately provokes an unhandled-if-unfixed access violation, so it needs its own process. Runs on both
# toolchains: the vectored handler under test is the backend's, and the fault is an OS property.
add_executable(trap_closed_window test_trap_closed_window.cpp)
target_link_libraries(trap_closed_window PRIVATE DetourModKit dmk_coverage)
target_include_directories(trap_closed_window PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(trap_closed_window PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(trap_closed_window)
add_dependencies(dmk_lifecycle_proof_hosts trap_closed_window)

dmk_add_raw_proof(NAME Lifecycle.TrapRetriesClosedWindowExecuteFault
  COMMAND $<TARGET_FILE:trap_closed_window> closed-window
  WORKING_DIRECTORY $<TARGET_FILE_DIR:trap_closed_window>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.TrapRetirementSerializesLateTransaction
  COMMAND $<TARGET_FILE:trap_closed_window> late-static
  WORKING_DIRECTORY $<TARGET_FILE_DIR:trap_closed_window>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# First-use logger state is allocation/language behavior, not loader behavior, so these cases run on both toolchains.
# The driver replaces plain global operator new for its single- and concurrent-OOM modes and also supplies a successful
# control. It links the archive so log()'s real construction path is exercised end to end; exit status is the oracle.
add_executable(logger_first_use_oom logger_first_use_oom.cpp)
target_link_libraries(logger_first_use_oom PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(logger_first_use_oom PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(logger_first_use_oom)
add_dependencies(dmk_lifecycle_proof_hosts logger_first_use_oom)

dmk_add_raw_proof(NAME Lifecycle.LoggerFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:logger_first_use_oom> oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_first_use_oom>
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.LoggerConcurrentFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:logger_first_use_oom> concurrent-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_first_use_oom>
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.LoggerFirstUseSuccessCreatesLiveSink
  COMMAND $<TARGET_FILE:logger_first_use_oom> success
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_first_use_oom>
  LABELS "lifecycle-proof")

# In the persistent-failure case the writer's batch reservation is refused for the whole run, so the regression is a
# hang rather than a wrong value. TEST_TIMEOUT is the oracle: without the one-record progress floor the writer spins
# and shutdown's join never returns. The host reaches into internal/ headers to drive one AsyncLogger directly.
add_executable(logger_writer_batch_oom logger_writer_batch_oom.cpp)
target_link_libraries(logger_writer_batch_oom PRIVATE DetourModKit dmk_coverage)
target_include_directories(logger_writer_batch_oom PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
dmk_static_runtime(logger_writer_batch_oom)
add_dependencies(dmk_lifecycle_proof_hosts logger_writer_batch_oom)

dmk_add_raw_proof(NAME Lifecycle.LoggerPersistentBatchOomStillDrainsAndJoins
  COMMAND $<TARGET_FILE:logger_writer_batch_oom> persistent-batch-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_writer_batch_oom>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.LoggerOversizeBatchSizeStillDrainsAndJoins
  COMMAND $<TARGET_FILE:logger_writer_batch_oom> oversize-batch
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_writer_batch_oom>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# The mode is observable only across process boundaries because each generation constructs a process-default logger.
# The host uses Session::start in one child and bootstrap in the next child over one shared file.
# Both toolchains run the proof because file open behavior belongs to the operating system.
add_executable(logger_generation_log logger_generation_log.cpp)
target_link_libraries(logger_generation_log PRIVATE DetourModKit dmk_coverage)
target_include_directories(logger_generation_log PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(logger_generation_log)
add_dependencies(dmk_lifecycle_proof_hosts logger_generation_log)

dmk_add_raw_proof(NAME Lifecycle.LoggerAppendModePreservesPriorGenerationRecords
  COMMAND $<TARGET_FILE:logger_generation_log> append-preserves
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_generation_log>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.LoggerDefaultOpenModeStartsACleanLog
  COMMAND $<TARGET_FILE:logger_generation_log> truncate-default
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_generation_log>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# The unknown-token control uses the rationale above the input_gate_abba control.
add_test(NAME Lifecycle.LoggerGenerationProofRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:logger_generation_log> no-such-scenario)
set_tests_properties(Lifecycle.LoggerGenerationProofRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:logger_generation_log>
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
add_dependencies(dmk_lifecycle_proof_hosts hook_instance_scope)

# The host loads its DLLs by bare name, which resolves from the application directory. The kits build into that
# directory already; hook_target_lib is declared one level up and has to be staged in.
add_custom_command(TARGET hook_instance_scope POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:hook_target_lib>
    $<TARGET_FILE_DIR:hook_instance_scope>)

# Each scenario is its own process so none inherits another's patches. The ctest name states the claim proved; the argv
# token stays the scenario keyword the host dispatches on.
set(hook_instance_scope_proofs
  Lifecycle.HookLedgerIsPerLinkedInstance           distinct
  Lifecycle.HookLedgerRefusesSameKitDuplicate       same-kit
  Lifecycle.HookLedgerIsBlindAcrossLinkedInstances  cross-kit
  Lifecycle.ArmedForeignHookIsRefusedByDecode       armed
  Lifecycle.HookRefusalCodesDistinguishTheMechanism codes)
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
# Unconditional, and so is the library's own definition under DMK_BUILD_TESTS, which is the only way this directory is
# added at all. A seam call in this host therefore needs no #if guard of its own; guarding one would be dead code.
target_compile_definitions(input_gate_abba PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(input_gate_abba)
add_dependencies(dmk_lifecycle_proof_hosts input_gate_abba)

dmk_add_raw_proof(NAME Lifecycle.CrossBindingReleaseHasNoABBA
  COMMAND $<TARGET_FILE:input_gate_abba>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RetiredPressCallableDisposalHasNoSelfDeadlock
  COMMAND $<TARGET_FILE:input_gate_abba> press-retire-disposal
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 10
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RetiredHoldCallableDisposalHasNoSelfDeadlock
  COMMAND $<TARGET_FILE:input_gate_abba> hold-retire-disposal
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 10
  LABELS "lifecycle-proof")

# The compositions the per-thread depth marker alone cannot answer: two threads inside cross-gate teardown consumer
# code with the exact TLS depth store refused on both at once. A regression is a mutual wait, so the timeout is the
# oracle rather than an assertion.
dmk_add_raw_proof(NAME InputLifecycleProof.CrossGateHoldTeardownSurvivesSimultaneousStoreFailure
  COMMAND $<TARGET_FILE:input_gate_abba> hold-store-failure-abba
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 30
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME InputLifecycleProof.CrossGateHoldRetirementSurvivesSimultaneousStoreFailure
  COMMAND $<TARGET_FILE:input_gate_abba> hold-retire-store-failure-abba
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 30
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME InputLifecycleProof.CrossGatePressDisposalSurvivesSimultaneousStoreFailure
  COMMAND $<TARGET_FILE:input_gate_abba> press-store-failure-abba
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 30
  LABELS "lifecycle-proof")

# Bounded negative cleanup control. It first parks a callback and observes join-before-clear from inside that body, then
# drives the ordinary ABBA loop through a live A registration whose B partner is deliberately refused. The second path
# pins cleanup ownership before either result can release a gate: without it A's balancing callback waits forever for B.
# An early clear reports from the first path, a missing unblock or owner hangs into TEST_TIMEOUT, and a missing rundown
# leaves the engine started. Exit zero requires released, stopped, then cleared, in that order.
dmk_add_raw_proof(NAME InputLifecycleProof.AbandonedParkedCallbackRunsDownBeforeClearing
  COMMAND $<TARGET_FILE:input_gate_abba> abandoned-parked-callback
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  TEST_TIMEOUT 30
  LABELS "lifecycle-proof")

# Negative control for the argv-selected scenarios above. They select on argv[1] inside a host that also carries the
# no-argument ABBA scenario, so a typo'd token, or a host built before a scenario existed, would silently run the ABBA
# case and exit 0 well inside TEST_TIMEOUT 10, a proof reporting PASS having asserted nothing about what it names.
# WILL_FAIL inverts the verdict, so this passes only while the host rejects a token it does not implement.
add_test(NAME Lifecycle.InputGateProofRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:input_gate_abba> no-such-scenario)
set_tests_properties(Lifecycle.InputGateProofRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_gate_abba>
  LABELS "lifecycle-proof")

# Run T-DISPATCH-COW in isolated processes. See docs/tests/README.md for the proof contract.
add_executable(dispatch_cow test_dispatch_cow.cpp)
target_link_libraries(dispatch_cow PRIVATE DetourModKit dmk_coverage)
target_include_directories(dispatch_cow PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(dispatch_cow)
add_dependencies(dmk_lifecycle_proof_hosts dispatch_cow)

set(dispatch_cow_proofs
  Lifecycle.DispatcherSubscribeCopiesNoCallableUnderLock  subscribe-copy-reentry
  Lifecycle.DispatcherCompactCopiesNoCallableUnderLock    compact-copy-reentry
  Lifecycle.DispatcherClearDestroysNoCallableUnderLock    clear-dtor-reentry
  Lifecycle.DispatcherResetDestroysNoCallableUnderLock    reset-dtor-reentry)
while(dispatch_cow_proofs)
  list(POP_FRONT dispatch_cow_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:dispatch_cow> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:dispatch_cow>
    TEST_TIMEOUT 30
    LABELS "lifecycle-proof")
endwhile()

# Reject unknown tokens so the host cannot report PASS for another scenario.
add_test(NAME Lifecycle.DispatchCowProofRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:dispatch_cow> no-such-scenario)
set_tests_properties(Lifecycle.DispatchCowProofRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:dispatch_cow>
  LABELS "lifecycle-proof")

# Each mode runs in a separate process because a lock-held capture destructor deadlocks. CTest uses the timeout as its
# oracle.
add_executable(input_reshape_retirement input_reshape_retirement.cpp)
target_link_libraries(input_reshape_retirement PRIVATE DetourModKit dmk_coverage)
target_include_directories(input_reshape_retirement PRIVATE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(input_reshape_retirement PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(input_reshape_retirement)
add_dependencies(dmk_lifecycle_proof_hosts input_reshape_retirement)

set(input_reshape_proofs
  InputLifecycleProof.RemovalDestroysCallablesOutsideFacadeMutex        pending-remove
  InputLifecycleProof.ClearDestroysCallablesOutsideFacadeMutex          pending-clear
  InputLifecycleProof.ShutdownDestroysCallablesOutsideFacadeMutex       pending-shutdown
  InputLifecycleProof.RebindDestroysCallablesOutsideFacadeMutex         pending-cardinality
  InputLifecycleProof.LiveRemovalDestroysCallablesOutsideBindingLock    live-remove
  InputLifecycleProof.LiveClearDestroysCallablesOutsideBindingLock      live-clear
  InputLifecycleProof.LiveRebindDestroysCallablesOutsideBindingLock     live-rebind)
while(input_reshape_proofs)
  list(POP_FRONT input_reshape_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:input_reshape_retirement> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:input_reshape_retirement>
    TEST_TIMEOUT 30
    LABELS "lifecycle-proof")
endwhile()

# Reject unknown tokens so the host cannot report PASS for another scenario.
add_test(NAME InputLifecycleProof.ReshapeProofRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:input_reshape_retirement> no-such-scenario)
set_tests_properties(InputLifecycleProof.ReshapeProofRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_reshape_retirement>
  LABELS "lifecycle-proof")

# Exhausting every TLS index is process-wide and irreversible for the delivery marker, so this needs its own host.
add_executable(input_tls_exhaustion input_tls_exhaustion.cpp)
target_link_libraries(input_tls_exhaustion PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(input_tls_exhaustion PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(input_tls_exhaustion PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(input_tls_exhaustion)
add_dependencies(dmk_lifecycle_proof_hosts input_tls_exhaustion)

dmk_add_raw_proof(NAME InputLifecycleProof.TlsExhaustionRefusesUntrackedDelivery
  COMMAND $<TARGET_FILE:input_tls_exhaustion> exhausted
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_tls_exhaustion>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# Positive control. The case above proves a zero callback count, which a binding that never matched would also produce.
dmk_add_raw_proof(NAME InputLifecycleProof.TrackedDeliveryIsAdmitted
  COMMAND $<TARGET_FILE:input_tls_exhaustion> available
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_tls_exhaustion>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# The reservation succeeds here and only the per-thread store fails, which index exhaustion cannot reach. Its own
# process because the facade drive it ends with starts and stops the real poll thread.
dmk_add_raw_proof(NAME InputLifecycleProof.TlsStoreFailureRefusesUntrackedDelivery
  COMMAND $<TARGET_FILE:input_tls_exhaustion> store-failure
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_tls_exhaustion>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# Bounded negative cleanup control for the facade drive the three scenarios above share. Its refusal exit used to clear
# a live key-state seam and return with the poll thread still running; this drives the same abandonment on purpose.
dmk_add_raw_proof(NAME InputLifecycleProof.AbandonedFacadeDrivePremiseRunsDownBeforeClearing
  COMMAND $<TARGET_FILE:input_tls_exhaustion> abandoned-premise
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_tls_exhaustion>
  TEST_TIMEOUT 30
  LABELS "lifecycle-proof")

# Negative control for the scenarios above, for the reason spelled out over the input_gate_abba control.
add_test(NAME InputLifecycleProof.TlsExhaustionProofRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:input_tls_exhaustion> no-such-scenario)
set_tests_properties(InputLifecycleProof.TlsExhaustionProofRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_tls_exhaustion>
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
add_dependencies(dmk_lifecycle_proof_hosts config_servicer_self_retire)

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
add_dependencies(dmk_lifecycle_proof_hosts input_self_shutdown)

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

# Bounded negative cleanup control for the three scenarios above. Their failure exits abandon a started engine whose
# callback captured stack state, and a self-shutdown hands its rundown to the reaper, so the engine reads as stopped
# while a callback can still run. Exit zero requires the parked body released, the deferred rundown observed complete,
# and only then the seam cleared.
dmk_add_raw_proof(NAME InputLifecycleProof.AbandonedSelfShutdownPremiseRunsDownBeforeClearing
  COMMAND $<TARGET_FILE:input_self_shutdown> abandoned-premise
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_self_shutdown>
  TEST_TIMEOUT 30
  LABELS "lifecycle-proof")

# First-use singleton state is allocation and language behavior, so these run on both toolchains. The driver replaces
# plain global operator new for its single- and concurrent-OOM modes and supplies a successful control.
add_executable(input_first_use_oom input_first_use_oom.cpp)
target_link_libraries(input_first_use_oom PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(input_first_use_oom PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(input_first_use_oom)
add_dependencies(dmk_lifecycle_proof_hosts input_first_use_oom)

dmk_add_raw_proof(NAME Lifecycle.InputFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:input_first_use_oom> oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_first_use_oom>
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.InputConcurrentFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:input_first_use_oom> concurrent-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_first_use_oom>
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.InputFirstUseSuccessStartsEngine
  COMMAND $<TARGET_FILE:input_first_use_oom> success
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_first_use_oom>
  LABELS "lifecycle-proof")

# Retention scenarios latch process-lifetime raw hook storage, while exception scenarios replace global allocation or
# backend behavior. Isolate every case, and give the reference-balance case sole ownership of its XInput module load.
add_executable(xinput_detour_rundown xinput_detour_rundown.cpp)
# The routed-unwind scenarios assert against the generated regions themselves, so this one host names the backend
# directly. Every other test target deliberately carries no backend include path.
target_link_libraries(xinput_detour_rundown PRIVATE DetourModKit safetyhook dmk_coverage psapi)
target_include_directories(xinput_detour_rundown PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(xinput_detour_rundown PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(xinput_detour_rundown)
add_dependencies(dmk_lifecycle_proof_hosts xinput_detour_rundown)

dmk_add_raw_proof(NAME Lifecycle.XInputTimeoutRetainsTrampolinesWithoutAllocating
  COMMAND $<TARGET_FILE:xinput_detour_rundown> timeout
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputPreBodyRouteRetainsExecutableChain
  COMMAND $<TARGET_FILE:xinput_detour_rundown> pre-body-route
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputActivePairSurvivesProcessExitStaticDestruction
  COMMAND $<TARGET_FILE:xinput_detour_rundown> process-exit-storage
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputCleanReleaseNeedsNoAllocation
  COMMAND $<TARGET_FILE:xinput_detour_rundown> clean-release-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputDrainedTeardownBalancesModuleReferences
  COMMAND $<TARGET_FILE:xinput_detour_rundown> reference-balance
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputFirstInstallOomFailsClosed
  COMMAND $<TARGET_FILE:xinput_detour_rundown> first-install-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputFirstInstallCreateOomFailsClosed
  COMMAND $<TARGET_FILE:xinput_detour_rundown> first-install-oom-create
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputEnableBeforeMutationExceptionIsContained
  COMMAND $<TARGET_FILE:xinput_detour_rundown> enable-before
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputEnableAfterMutationExceptionIsReconciled
  COMMAND $<TARGET_FILE:xinput_detour_rundown> enable-after
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputDisableBeforeMutationExceptionRetainsChain
  COMMAND $<TARGET_FILE:xinput_detour_rundown> disable-before
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputDisableAfterMutationExceptionReconcilesOriginal
  COMMAND $<TARGET_FILE:xinput_detour_rundown> disable-after
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputExDisableExceptionRetainsPrimary
  COMMAND $<TARGET_FILE:xinput_detour_rundown> disable-ex-before
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputPrimaryDisableExceptionCompensatesThePair
  COMMAND $<TARGET_FILE:xinput_detour_rundown> disable-primary-before
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputInstallRecoversTheRetainedExMember
  COMMAND $<TARGET_FILE:xinput_detour_rundown> pair-compensation-inverted
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputNewerLayerSurvivesRawTeardown
  COMMAND $<TARGET_FILE:xinput_detour_rundown> newer-layer
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputNewerLayerRetainsExPair
  COMMAND $<TARGET_FILE:xinput_detour_rundown> newer-layer-ex
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

# Latches a process-lifetime permanent detour like the timeout case, so it also needs its own process.
dmk_add_raw_proof(NAME Lifecycle.XInputCommittedArmInversionRetainsTrampoline
  COMMAND $<TARGET_FILE:xinput_detour_rundown> arm-inversion
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputUnownedExportDoesNotStrandThePair
  COMMAND $<TARGET_FILE:xinput_detour_rundown> ex-arm-inversion
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

# The primary-loss direction of the pair transaction, one process per state the loss is staged from: during the
# ordinal-100 arm of a fresh install, after a complete pair is already published, and against retained storage. Each
# latches a published or permanent route, so none may share a process.
dmk_add_raw_proof(NAME Lifecycle.XInputPrimaryLostDuringExArmDegradesThePair
  COMMAND $<TARGET_FILE:xinput_detour_rundown> fresh-primary-loss
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputInstalledPairMaintenanceRecoversALostPrimary
  COMMAND $<TARGET_FILE:xinput_detour_rundown> installed-primary-loss
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputRetainedPairRecoversALostPrimary
  COMMAND $<TARGET_FILE:xinput_detour_rundown> permanent-primary-loss
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

# The production caller of that maintenance. Every mode above drives install_xinput() directly, so the poll loop's own
# decision to keep calling it after publication is unproven without a real poll thread doing the recovery.
dmk_add_raw_proof(NAME Lifecycle.XInputPollLoopMaintainsAPublishedPair
  COMMAND $<TARGET_FILE:xinput_detour_rundown> poller-maintains-pair
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

# Routed-wrapper unwind and retained-chain capacity. Each case latches process-wide state (registered unwind records,
# a published route, or a temporarily lowered ceiling), so none of them may share a process with another.
dmk_add_raw_proof(NAME Lifecycle.RoutedWrapperIsUnwindable
  COMMAND $<TARGET_FILE:xinput_detour_rundown> wrapper-unwind
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RoutedWrapperPropagatesNativeExceptions
  COMMAND $<TARGET_FILE:xinput_detour_rundown> wrapper-native-exception
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RefusedUnwindRegistrationRollsBack
  COMMAND $<TARGET_FILE:xinput_detour_rundown> unwind-registration-refused
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.PublishedRouteMetadataIsRetained
  COMMAND $<TARGET_FILE:xinput_detour_rundown> route-metadata-retained
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RouteCapacityRefusesBeforePublication
  COMMAND $<TARGET_FILE:xinput_detour_rundown> route-capacity-refusal
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputPairReservesCapacityAtomically
  COMMAND $<TARGET_FILE:xinput_detour_rundown> xinput-pair-capacity
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RefusedUnwindUnregistrationRetainsStorage
  COMMAND $<TARGET_FILE:xinput_detour_rundown> unwind-unregistration-refused
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RouteCapacityOverflowRefusesCleanly
  COMMAND $<TARGET_FILE:xinput_detour_rundown> route-capacity-overflow
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RouteRestoreFailureChargesPublication
  COMMAND $<TARGET_FILE:xinput_detour_rundown> route-restore-failure
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.RouteAllocatorReclaimsWholeBlock
  COMMAND $<TARGET_FILE:xinput_detour_rundown> route-allocator-reclamation
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.MidRouteAccountingIncludesGeneratedStub
  COMMAND $<TARGET_FILE:xinput_detour_rundown> mid-route-accounting
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_detour_rundown>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# The local and forwarding proxy DLLs make both ordinal-100 module-ownership branches deterministic. They share the
# host's output directory, so bare-name loading resolves the paired fixtures on both generators.
add_library(xinput_forwarding_proxy_local SHARED
  xinput_local_ex_proxy_dll.cpp
  xinput_local_ex_proxy.def)
set_target_properties(xinput_forwarding_proxy_local PROPERTIES PREFIX "" OUTPUT_NAME "dmk_xinput_proxy_local")
dmk_static_runtime(xinput_forwarding_proxy_local SHARED)
add_dependencies(xinput_detour_rundown xinput_forwarding_proxy_local)

# Ordinal 100 forwards to the local proxy so GetProcAddress resolves it in another module. GNU ld reads the forwarder
# from the .def. MSVC LINK does not honor a .def or /EXPORT "name = othermodule.func" as a cross-module forwarder
# unless it already knows the target module: without that it resolves XInputGetStateExLocal as a local symbol and fails
# with LNK2001. So on MSVC the forwarder and the local ordinal-1 export are declared with /EXPORT, and the local
# proxy's import library is linked to name the module. Both toolchains then produce the same export table: a local
# XInputGetState @1 and a NONAME forwarder @100.
add_library(xinput_forwarding_proxy_fwd SHARED xinput_forwarding_proxy_dll.cpp)
set_target_properties(xinput_forwarding_proxy_fwd PROPERTIES PREFIX "" OUTPUT_NAME "dmk_xinput_proxy_fwd")
add_dependencies(xinput_forwarding_proxy_fwd xinput_forwarding_proxy_local)
if(MSVC)
  target_link_libraries(xinput_forwarding_proxy_fwd PRIVATE xinput_forwarding_proxy_local)
  target_link_options(xinput_forwarding_proxy_fwd PRIVATE
    "/EXPORT:XInputGetState,@1"
    "/EXPORT:XInputGetStateEx=dmk_xinput_proxy_local.XInputGetStateExLocal,@100,NONAME")
else()
  target_sources(xinput_forwarding_proxy_fwd PRIVATE xinput_forwarding_proxy.def)
endif()
dmk_static_runtime(xinput_forwarding_proxy_fwd SHARED)

# The two exempt export shapes. Both reuse the forwarding proxy's translation unit, which defines only a local
# XInputGetState, so the .def alone decides whether ordinal 100 is absent or an alias of the primary export. Without
# these the exemptions are host-dependent: a runtime that happens to publish a distinct ordinal 100 never exercises
# them, and the alias branch that stops a second inline hook from capturing the first hook's jump as its original has
# no deterministic proof at all.
add_library(xinput_absent_ex_proxy SHARED
  xinput_forwarding_proxy_dll.cpp
  xinput_absent_ex_proxy.def)
set_target_properties(xinput_absent_ex_proxy PROPERTIES PREFIX "" OUTPUT_NAME "dmk_xinput_proxy_noex")
dmk_static_runtime(xinput_absent_ex_proxy SHARED)

add_library(xinput_alias_ex_proxy SHARED
  xinput_forwarding_proxy_dll.cpp
  xinput_alias_ex_proxy.def)
set_target_properties(xinput_alias_ex_proxy PROPERTIES PREFIX "" OUTPUT_NAME "dmk_xinput_proxy_alias")
dmk_static_runtime(xinput_alias_ex_proxy SHARED)

add_executable(xinput_forwarding_guard xinput_forwarding_guard.cpp)
add_dependencies(xinput_forwarding_guard xinput_forwarding_proxy_fwd xinput_forwarding_proxy_local
  xinput_absent_ex_proxy xinput_alias_ex_proxy)
target_link_libraries(xinput_forwarding_guard PRIVATE DetourModKit dmk_coverage psapi)
target_include_directories(xinput_forwarding_guard PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(xinput_forwarding_guard PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(xinput_forwarding_guard)
add_dependencies(dmk_lifecycle_proof_hosts xinput_forwarding_guard)

dmk_add_raw_proof(NAME Lifecycle.XInputForwardedExOrdinalIsHooked
  COMMAND $<TARGET_FILE:xinput_forwarding_guard> forwarded
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_forwarding_guard>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputSameModuleExOrdinalIsHooked
  COMMAND $<TARGET_FILE:xinput_forwarding_guard> same-module
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_forwarding_guard>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputAbsentExOrdinalIsCompleteCoverage
  COMMAND $<TARGET_FILE:xinput_forwarding_guard> absent-ex
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_forwarding_guard>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.XInputAliasedExOrdinalIsCompleteCoverage
  COMMAND $<TARGET_FILE:xinput_forwarding_guard> alias-ex
  WORKING_DIRECTORY $<TARGET_FILE_DIR:xinput_forwarding_guard>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# Compiling profiler.cpp directly lets the poisoning allocator govern its ring, and keeps the driver free of any
# archive allocation the size threshold would have to distinguish. Coverage is excluded because gcov may allocate
# during process teardown, which is exactly the window this proof poisons.
add_executable(profiler_late_uaf
  test_profiler_late_uaf.cpp
  ${PROJECT_SOURCE_DIR}/src/profiler.cpp)
target_include_directories(profiler_late_uaf PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(profiler_late_uaf)
add_dependencies(dmk_lifecycle_proof_hosts profiler_late_uaf)

dmk_add_raw_proof(NAME Lifecycle.ProfilerLateScopedProfileNoUAF
  COMMAND $<TARGET_FILE:profiler_late_uaf>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:profiler_late_uaf>
  LABELS "lifecycle-proof")

# The profiler ring is the only allocation first use makes, so poisoning the global operators isolates it exactly.
# Allocation and language behavior, so both toolchains run it.
add_executable(profiler_first_use_oom profiler_first_use_oom.cpp)
target_link_libraries(profiler_first_use_oom PRIVATE DetourModKit dmk_coverage)
target_include_directories(profiler_first_use_oom PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(profiler_first_use_oom)
add_dependencies(dmk_lifecycle_proof_hosts profiler_first_use_oom)

dmk_add_raw_proof(NAME Lifecycle.ProfilerFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:profiler_first_use_oom> oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:profiler_first_use_oom>
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.ProfilerConcurrentFirstUseOomFailsClosed
  COMMAND $<TARGET_FILE:profiler_first_use_oom> concurrent-oom
  WORKING_DIRECTORY $<TARGET_FILE_DIR:profiler_first_use_oom>
  SKIP_RETURN_CODE 77
  LABELS "lifecycle-proof")

dmk_add_raw_proof(NAME Lifecycle.ProfilerFirstUseSuccessPublishesFullRing
  COMMAND $<TARGET_FILE:profiler_first_use_oom> success
  WORKING_DIRECTORY $<TARGET_FILE_DIR:profiler_first_use_oom>
  LABELS "lifecycle-proof")

# Static-destruction order is a language guarantee, not loader behavior, so the late-emitter proof runs on both
# toolchains. Its verdict is the exit code after main returns, which no in-process test framework can observe.
add_executable(diagnostics_late_emitter diagnostics_late_emitter.cpp)
target_link_libraries(diagnostics_late_emitter PRIVATE DetourModKit dmk_coverage)
target_include_directories(diagnostics_late_emitter PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(diagnostics_late_emitter)
add_dependencies(dmk_lifecycle_proof_hosts diagnostics_late_emitter)

dmk_add_raw_proof(NAME DiagnosticsLifecycleProof.LatePinnedEmitterCannotTouchDestroyedState
  COMMAND $<TARGET_FILE:diagnostics_late_emitter>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:diagnostics_late_emitter>
  LABELS "lifecycle-proof")

# Load-time allocation failure is loader-independent language behavior, so this runs on both toolchains. One source
# builds twice: the probe DLL arms its poison before its own initializers and links the archive, so DMK's static
# initialization is what the poison governs; the host only loads it and reads the verdict. The host must NOT link the
# archive, or its own copy of DMK would initialize first, outside the poisoned window.
#
# dmk_coverage is required, not optional: the archive is instrumented directly, so a final link without it fails on
# undefined __gcov_init / __gcov_exit / __gcov_merge_add. It is also safe here, unlike profiler_late_uaf, which opts
# out. gcov registers through atexit and writes .gcda through C malloc, neither of which the replaced operator new
# intercepts, so a flush that runs while the poison is still armed (the one path that reaches it is a probe DLL built
# without its export, which already fails the proof) completes normally instead of faulting.
add_library(diagnostics_oom_probe SHARED diagnostics_first_use_oom.cpp)
set_target_properties(diagnostics_oom_probe PROPERTIES PREFIX "" OUTPUT_NAME "dmk_diagnostics_oom_probe")
target_compile_definitions(diagnostics_oom_probe PRIVATE DMK_DIAGNOSTICS_OOM_PROBE_DLL)
target_link_libraries(diagnostics_oom_probe PRIVATE DetourModKit dmk_coverage)
target_include_directories(diagnostics_oom_probe PRIVATE ${PROJECT_SOURCE_DIR}/include)
dmk_static_runtime(diagnostics_oom_probe SHARED)

add_executable(diagnostics_first_use_oom diagnostics_first_use_oom.cpp)
add_dependencies(diagnostics_first_use_oom diagnostics_oom_probe)
dmk_static_runtime(diagnostics_first_use_oom)
add_dependencies(dmk_lifecycle_proof_hosts diagnostics_first_use_oom)

dmk_add_raw_proof(NAME DiagnosticsLifecycleProof.PoisonedModuleLoadReportsExactZeroPopulation
  COMMAND $<TARGET_FILE:diagnostics_first_use_oom> poisoned-load
  WORKING_DIRECTORY $<TARGET_FILE_DIR:diagnostics_first_use_oom>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# Loader reference counting is OS behavior, not runtime behavior: LoadLibrary/FreeLibrary transitions and the
# DLL_PROCESS_DETACH notification are identical under both toolchains, and the archive links into a SHARED target on
# both (as kit_a/kit_b above already demonstrate). So these run on both toolchains.
# The probe DLL links coverage because it consumes the instrumented archive.
add_library(bootstrap_probe SHARED bootstrap_probe_dll.cpp)
set_target_properties(bootstrap_probe PROPERTIES PREFIX "" OUTPUT_NAME "bootstrap_probe")
target_link_libraries(bootstrap_probe PRIVATE DetourModKit dmk_coverage)
target_include_directories(bootstrap_probe PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(bootstrap_probe PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(bootstrap_probe SHARED)

# The loader host and its companion DLL share an output directory so bare-name loading is deterministic.
add_executable(bootstrap_module_ref test_bootstrap_module_ref.cpp)
add_dependencies(bootstrap_module_ref bootstrap_probe)
dmk_static_runtime(bootstrap_module_ref)
add_dependencies(dmk_lifecycle_proof_hosts bootstrap_module_ref)

dmk_add_raw_proof(NAME Lifecycle.BootstrapWorkerStaysMapped
  COMMAND $<TARGET_FILE:bootstrap_module_ref> mapped
  WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
  LABELS "lifecycle-proof")
dmk_add_raw_proof(NAME Lifecycle.BootstrapAttachPerformsNoHeapSetup
  COMMAND $<TARGET_FILE:bootstrap_module_ref> leaf
  WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
  LABELS "lifecycle-proof")
dmk_add_raw_proof(NAME Lifecycle.BootstrapWorkerDrainedUnloads
  COMMAND $<TARGET_FILE:bootstrap_module_ref> unload
  WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
  LABELS "lifecycle-proof")
dmk_add_raw_proof(NAME Lifecycle.BootstrapBareFreeLibrarySelfDrains
  COMMAND $<TARGET_FILE:bootstrap_module_ref> bare
  WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
  LABELS "lifecycle-proof")
dmk_add_raw_proof(NAME Lifecycle.BootstrapProcessExitWithLiveWorker
  COMMAND $<TARGET_FILE:bootstrap_module_ref> exit
  WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
  LABELS "lifecycle-proof")
dmk_add_raw_proof(NAME Lifecycle.ReloadServicerProcessExitNeverWaitsOnOwnedMutex
  COMMAND $<TARGET_FILE:bootstrap_module_ref> reload-exit
  WORKING_DIRECTORY $<TARGET_FILE_DIR:bootstrap_module_ref>
  TEST_TIMEOUT 10
  LABELS "lifecycle-proof")

# The bare-FreeLibrary input proof reaches Input static destruction under the real loader lock.
# Both toolchains use the same loader and CRT contract.
add_library(input_loader_probe SHARED input_loader_detach_dll.cpp)
set_target_properties(input_loader_probe PROPERTIES PREFIX "" OUTPUT_NAME "input_loader_probe")
target_link_libraries(input_loader_probe PRIVATE DetourModKit dmk_coverage)
target_include_directories(input_loader_probe PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
# The exported facade-mutex hold routes through the DMK_ENABLE_TEST_SEAMS-gated seam in the archive.
target_compile_definitions(input_loader_probe PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(input_loader_probe SHARED)

add_executable(input_loader_detach test_input_loader_detach.cpp)
add_dependencies(input_loader_detach input_loader_probe)
dmk_static_runtime(input_loader_detach)
add_dependencies(dmk_lifecycle_proof_hosts input_loader_detach)

dmk_add_raw_proof(NAME Lifecycle.InputLoaderDetachRetainsCompleteOwner
  COMMAND $<TARGET_FILE:input_loader_detach>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:input_loader_detach>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# bootstrap_detach(nullptr) leaves the process-wide bootstrap slot terminally Detached, so this case cannot share the
# unit binary with any later bootstrap. It compiles the unit tree's allocation probe so the terminal refusal can be
# proved to allocate nothing, and needs the test seams for the forced loader-lock probe.
add_executable(session_detach_terminal
  session_detach_terminal.cpp
  "${CMAKE_CURRENT_SOURCE_DIR}/../test_alloc_probe.cpp")
target_link_libraries(session_detach_terminal PRIVATE DetourModKit dmk_coverage)
target_include_directories(session_detach_terminal PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src
  ${PROJECT_SOURCE_DIR}/tests)
target_compile_definitions(session_detach_terminal PRIVATE DMK_ENABLE_TEST_SEAMS)
dmk_static_runtime(session_detach_terminal)
add_dependencies(dmk_lifecycle_proof_hosts session_detach_terminal)

dmk_add_raw_proof(NAME Lifecycle.DetachAfterDrainRevokesBlockingAuthorization
  COMMAND $<TARGET_FILE:session_detach_terminal>
  WORKING_DIRECTORY $<TARGET_FILE_DIR:session_detach_terminal>
  TEST_TIMEOUT 60
  LABELS "lifecycle-proof")

# The long-lived host. Its four scenarios reach terminal states that cannot coexist in one process: a drained
# generation, a refused concurrent drain, an abandoned-and-pinned bootstrap, and a live session carried into CRT
# teardown. Each is therefore its own registered proof over the same binary. It links the archive because the whole
# point is to drive the real process-global subsystems, and it needs src/ on the include path for the internal lifecycle
# control block whose published context the misuse scenario asserts.
add_executable(full_lifecycle test_full_lifecycle.cpp)
target_link_libraries(full_lifecycle PRIVATE DetourModKit dmk_coverage)
target_include_directories(full_lifecycle PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
dmk_static_runtime(full_lifecycle)
add_dependencies(dmk_lifecycle_proof_hosts full_lifecycle)

# The ctest name states the claim proved; the argv token stays the scenario keyword the host dispatches on. Both are
# spelled out so the registered test name is greppable in this file, matching the hook_instance_scope list above.
set(full_lifecycle_proofs
  Lifecycle.FullLifecycleCycles     cycles
  Lifecycle.FullLifecycleConcurrent concurrent
  Lifecycle.FullLifecycleMisuse     misuse
  Lifecycle.FullLifecycleExit       exit)
while(full_lifecycle_proofs)
  list(POP_FRONT full_lifecycle_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:full_lifecycle> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:full_lifecycle>
    LABELS "lifecycle-proof")
endwhile()

# The callback-only Logic DLL. It gets neither DetourModKit nor the include path that would let it reach the archive's
# headers, which is the property under test rather than an oversight: another library instance could add independent
# process state and install-time self-references to the unmap verdict. Everything it needs is in
# logic_dll_protocol.hpp, which forward-declares the one DetourModKit type a mid detour names. It links no archive, so
# it performs no final link of the instrumented library and must not carry dmk_coverage.
add_library(logic_callback_dll SHARED logic_callback_dll.cpp)
set_target_properties(logic_callback_dll PROPERTIES PREFIX "" OUTPUT_NAME "logic_callback_dll")
dmk_static_runtime(logic_callback_dll SHARED)

# The host owns DetourModKit, every Hook, and every binding. It needs src/ on the include path for the poll loop's
# key-state seam, which is the only way to drive a binding without real hardware.
add_executable(logic_dll_unload test_logic_dll_unload.cpp)
target_link_libraries(logic_dll_unload PRIVATE DetourModKit dmk_coverage)
target_include_directories(logic_dll_unload PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(logic_dll_unload PRIVATE DMK_ENABLE_TEST_SEAMS)
add_dependencies(logic_dll_unload logic_callback_dll hook_target_lib)
dmk_static_runtime(logic_dll_unload)
add_dependencies(dmk_lifecycle_proof_hosts logic_dll_unload)

# Both companions load by bare name from the application directory. logic_callback_dll is declared here and already
# builds into it; hook_target_lib is declared one level up and has to be staged in.
add_custom_command(TARGET logic_dll_unload POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:hook_target_lib>
    $<TARGET_FILE_DIR:logic_dll_unload>)

# Each scenario reaches a terminal process state the others cannot share: a completed drain latches callback staging
# open, a refused one latches it closed for good, and a pinned hook leaks its adapter slot for the process lifetime.
# The ctest name states the claim proved; the argv token stays the scenario keyword the host dispatches on.
set(logic_dll_unload_proofs
  Lifecycle.LogicDllDrainReleasesEveryStagedCallable      input-drained
  Lifecycle.LogicDllRetainedGuardCannotKeepCallableAlive  guard-retained
  Lifecycle.LogicDllHeldBindingIsBalancedByTheDrain       guard-retained-hold
  Lifecycle.LogicDllParkedInputCallbackRefusesUnload      input-parked
  Lifecycle.LogicDllParkedConfigSetterRefusesUnload       config-setter-parked
  Lifecycle.LogicDllParkedConfigCallbackRefusesUnload     config-parked
  Lifecycle.LogicDllMidTeardownWaitsForParkedCallback     mid-parked
  Lifecycle.LogicDllMidPreAdapterRouteDrainsBeforeUnload  mid-route-pre
  Lifecycle.LogicDllMidPostAdapterRouteDrainsBeforeUnload mid-route-post
  Lifecycle.LogicDllPinnedMidStubStaysInertAfterUnload    mid-pinned
  Lifecycle.LogicDllInlineCallerQuiescenceAllowsUnload    inline-quiesced)
while(logic_dll_unload_proofs)
  list(POP_FRONT logic_dll_unload_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:logic_dll_unload> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:logic_dll_unload>
    TEST_TIMEOUT 60
    LABELS "lifecycle-proof")
endwhile()

# The generation target links one archive instance. Test seams replace its window and XInput dependencies.
add_library(staged_generation_dll SHARED staged_generation_dll.cpp)
set_target_properties(staged_generation_dll PROPERTIES PREFIX "" OUTPUT_NAME "staged_generation_dll")
target_link_libraries(staged_generation_dll PRIVATE DetourModKit dmk_coverage)
target_include_directories(staged_generation_dll PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(staged_generation_dll PRIVATE DMK_ENABLE_TEST_SEAMS)
add_dependencies(staged_generation_dll hook_target_lib xinput_forwarding_proxy_local)
dmk_static_runtime(staged_generation_dll SHARED)

# The host links a separate archive instance for the clear-bindings proof.
add_executable(staged_generation_soak staged_generation_soak.cpp)
target_link_libraries(staged_generation_soak PRIVATE DetourModKit DetourModKit::WheelHost dmk_coverage)
target_include_directories(staged_generation_soak PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(staged_generation_soak PRIVATE DMK_ENABLE_TEST_SEAMS)
add_dependencies(staged_generation_soak staged_generation_dll xinput_forwarding_proxy_local hook_target_lib)
dmk_static_runtime(staged_generation_soak)
add_dependencies(dmk_lifecycle_proof_hosts staged_generation_soak)

# The parent fixture needs a copy beside the host. The other DLL fixtures already use this output directory.
add_custom_command(TARGET staged_generation_soak POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:hook_target_lib>
    $<TARGET_FILE_DIR:staged_generation_soak>)

# Pinned images release their file handles only after the scenario process exits. The fixture removes only staged files.
set(_dmk_staged_generation_cleanup_script
  "${CMAKE_CURRENT_BINARY_DIR}/staged_generation_artifact_cleanup.cmake")
file(GENERATE OUTPUT "${_dmk_staged_generation_cleanup_script}" CONTENT [=[
cmake_minimum_required(VERSION 3.28)

if(NOT DEFINED STAGED_GENERATION_DIRECTORY OR STAGED_GENERATION_DIRECTORY STREQUAL "")
  message(FATAL_ERROR "STAGED_GENERATION_DIRECTORY must name the staged-generation output directory.")
endif()

cmake_path(ABSOLUTE_PATH STAGED_GENERATION_DIRECTORY NORMALIZE
  OUTPUT_VARIABLE _staged_generation_directory)
file(GLOB _staged_generation_artifacts LIST_DIRECTORIES FALSE
  "${_staged_generation_directory}/staged_generation.p*_g*.dll"
  "${_staged_generation_directory}/staged_gen_*.p*_n*.log")
foreach(_staged_generation_artifact IN LISTS _staged_generation_artifacts)
  cmake_path(GET _staged_generation_artifact PARENT_PATH _staged_generation_artifact_directory)
  cmake_path(NORMAL_PATH _staged_generation_artifact_directory
    OUTPUT_VARIABLE _staged_generation_normalized_artifact_directory)
  if(NOT _staged_generation_normalized_artifact_directory STREQUAL _staged_generation_directory)
    message(FATAL_ERROR "A staged-generation artifact escaped the cleanup directory.")
  endif()

  file(REMOVE "${_staged_generation_artifact}")
  if(EXISTS "${_staged_generation_artifact}")
    message(FATAL_ERROR "Cleanup left a staged-generation artifact at ${_staged_generation_artifact}.")
  endif()
endforeach()
]=])
add_test(NAME StagedGenerationArtifactCleanup
  COMMAND "${CMAKE_COMMAND}"
    "-DSTAGED_GENERATION_DIRECTORY=$<TARGET_FILE_DIR:staged_generation_soak>"
    -P "${_dmk_staged_generation_cleanup_script}")
set_tests_properties(StagedGenerationArtifactCleanup PROPERTIES
  FIXTURES_CLEANUP dmk_staged_generation_artifacts
  TIMEOUT 30)

# This dependency starts a configure pass after an InputPoller source edit. The pass requires one owner uninstall site.
set(_dmk_input_poller_source "${PROJECT_SOURCE_DIR}/src/internal/input_poller.cpp")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_dmk_input_poller_source}")
file(READ "${_dmk_input_poller_source}" _dmk_input_poller_text)
string(REGEX REPLACE "[ \t\r\n]" "" _dmk_input_poller_compact "${_dmk_input_poller_text}")
string(REGEX MATCHALL "uninstall\\(m_intercept_owner\\)" _dmk_intercept_uninstall_calls
  "${_dmk_input_poller_compact}")
list(LENGTH _dmk_intercept_uninstall_calls _dmk_intercept_uninstall_call_count)
if(NOT _dmk_intercept_uninstall_call_count EQUAL 1)
  message(FATAL_ERROR
    "InputPoller must contain exactly one uninstall(m_intercept_owner) call site. The configure gate found "
    "${_dmk_intercept_uninstall_call_count}.")
endif()

# The resident-host soak is a required gate. A missing window station must fail instead of reporting success.
# 1200 seconds covers the 100 generations on a coverage-instrumented hosted runner; local Debug runs take under
# three minutes.
dmk_add_raw_proof(NAME Lifecycle.StagedGenerationSoakReloadsWithFreshBytes
  COMMAND $<TARGET_FILE:staged_generation_soak> soak
  WORKING_DIRECTORY $<TARGET_FILE_DIR:staged_generation_soak>
  TEST_TIMEOUT 1200
  LABELS "lifecycle-proof")
set_tests_properties(Lifecycle.StagedGenerationSoakReloadsWithFreshBytes PROPERTIES
  FIXTURES_REQUIRED dmk_staged_generation_artifacts)

# These scenarios require a window station. CTest treats exit 77 as a host skip.
set(staged_generation_window_proofs
  Lifecycle.StagedGenerationLocalWheelRetentionStaysMapped      local-wheel-retention
  Lifecycle.StagedGenerationReloadNeverUninstallsInterception   uninstall-call-site)
while(staged_generation_window_proofs)
  list(POP_FRONT staged_generation_window_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:staged_generation_soak> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:staged_generation_soak>
    TEST_TIMEOUT 120
    SKIP_RETURN_CODE 77
    LABELS "lifecycle-proof")
  set_tests_properties(${proof_name} PROPERTIES FIXTURES_REQUIRED dmk_staged_generation_artifacts)
endwhile()

# These scenarios use deterministic fixtures or no platform fixture. Exit 77 reports a failure.
set(staged_generation_required_proofs
  Lifecycle.StagedGenerationForeignXInputRetainsThePair     foreign-xinput
  Lifecycle.StagedGenerationParkedCallbackRefusesReload     parked-callback
  Lifecycle.StagedGenerationReleasedCallbackAllowsReload    drain-retry
  Lifecycle.StagedGenerationPartialInitRollsBackAndUnmaps   partial-init)
while(staged_generation_required_proofs)
  list(POP_FRONT staged_generation_required_proofs proof_name scenario)
  dmk_add_raw_proof(NAME ${proof_name}
    COMMAND $<TARGET_FILE:staged_generation_soak> ${scenario}
    WORKING_DIRECTORY $<TARGET_FILE_DIR:staged_generation_soak>
    TEST_TIMEOUT 120
    LABELS "lifecycle-proof")
  set_tests_properties(${proof_name} PROPERTIES FIXTURES_REQUIRED dmk_staged_generation_artifacts)
endwhile()

# The negative control keeps an unknown token distinct from a successful scenario.
add_test(NAME Lifecycle.StagedGenerationProofRejectsAnUnknownScenario
  COMMAND $<TARGET_FILE:staged_generation_soak> no-such-scenario)
set_tests_properties(Lifecycle.StagedGenerationProofRejectsAnUnknownScenario PROPERTIES
  WILL_FAIL TRUE
  TIMEOUT 10
  WORKING_DIRECTORY $<TARGET_FILE_DIR:staged_generation_soak>
  LABELS "lifecycle-proof")
