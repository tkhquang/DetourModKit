cmake_minimum_required(VERSION 3.28)

# Test and benchmark TUs include Win32 implementation headers directly; keep their macro policy local to this
# directory so it cannot reach an add_subdirectory or installed-package consumer. The package consumer projects
# configure standalone (never via add_subdirectory from here), and their windows_macro_probe TUs fail the build if
# NOMINMAX ever reaches a consumer compile line, so the directory-wide form cannot leak past the tests.
if(WIN32)
  add_compile_definitions(NOMINMAX)
endif()

# The DMKBuildSettings warning and hardening lists apply directory-scoped over this proof tree: every target
# here (and in fault/ and lifecycle/) is first-party, so one directory command replaces per-target application
# on dozens of proof hosts without reaching any consumer scope. GoogleTest configures inside this directory and
# inherits the flags; the explicit per-target -w suppression below keeps its diagnostics quiet, as before.
add_compile_options(${DMK_WARNING_COMPILE_OPTIONS} ${DMK_HARDENING_COMPILE_OPTIONS})
add_link_options(${DMK_HARDENING_LINK_OPTIONS})

# Compile the benchmark ledger itself as a standalone producer proof. Keeping the mode-driven main behind a private
# definition in the shared header makes every probe exercise the exact code the four benchmarks include, without a
# second implementation that could drift. This target exists in tests-ON and benchmarks-ON trees.
set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/bench_gate.hpp" PROPERTIES LANGUAGE CXX)
add_executable(dmk_bench_gate_probe "${CMAKE_CURRENT_SOURCE_DIR}/bench_gate.hpp")
target_compile_definitions(dmk_bench_gate_probe PRIVATE DMK_BENCH_GATE_PROBE_MAIN)
dmk_static_runtime(dmk_bench_gate_probe)

if(DMK_BUILD_TESTS)
  # Prefer a system/pre-provisioned GoogleTest (>= 1.17) so an offline or CI machine with a system GTest skips the
  # network fetch; otherwise fall back to a pinned FetchContent clone. Both paths provide the GTest::gtest_main
  # target the tests link against, so no link-line change is needed for either.
  find_package(GTest 1.17 QUIET)

  if(NOT GTest_FOUND OR NOT TARGET GTest::gtest_main)
    include(FetchContent)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG 52eb8108c5bdec04579160ae17225d66034bd723 # v1.17.0 release commit
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    # GoogleTest is a build-time test dependency only; do not install its headers, libs, or package config through
    # DetourModKit's install target.
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()

  # This executable is a dispatch-only negative control for the blocking MSVC ASan workflow. It is never part of the
  # ordinary build or CTest suite; the deliberate-red workflow mode names the target explicitly. The unit-test glob
  # below is anchored to main.cpp and test_*.cpp rather than *.cpp, so this TU's own main() cannot be swept into
  # DetourModKit_tests; keep both that anchoring and this file's name outside those patterns.
  if(MSVC AND DMK_ENABLE_SANITIZERS)
    add_executable(dmk_asan_failure_probe EXCLUDE_FROM_ALL asan_failure_probe.cpp)
    dmk_static_runtime(dmk_asan_failure_probe)

    # The workflow runs this target by path, and a Failure from a path that no longer exists is indistinguishable
    # from the sanitizer red the run is supposed to prove. Publish the generator's own answer so the run step cannot
    # drift from whatever layout the active preset and generator produce.
    file(GENERATE
      OUTPUT "${CMAKE_BINARY_DIR}/dmk_asan_failure_probe_path.txt"
      CONTENT "$<TARGET_FILE:dmk_asan_failure_probe>")
  endif()

  # Suppress warnings from GoogleTest sources
  foreach(_ext_target gtest gtest_main gmock gmock_main)
    if(TARGET ${_ext_target})
      target_compile_options(${_ext_target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-w>
        $<$<CXX_COMPILER_ID:MSVC>:/w>
      )
    endif()
  endforeach()

  # A DLL cannot be fully static, but embedding the gcc and standard-library runtimes avoids mismatched copies on PATH.
  # The module definition file adds the two aliased export names the quorum-provenance proof needs; it must list every
  # other export as well, because it replaces the automatic export set on the GNU toolchain.
  add_library(hook_target_lib SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hook_target_lib.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hook_target_lib.def"
  )
  set_target_properties(hook_target_lib PROPERTIES
    PREFIX ""
    OUTPUT_NAME "hook_target_lib"
  )
  dmk_static_runtime(hook_target_lib SHARED)

  # The RTTI generation fixture is linked once and rewritten into two images that share a base, a SizeOfImage, and a
  # TimeDateStamp. ASLR is disabled for it so both variants map at the link's preferred base: the defect under proof is
  # a DIFFERENT image at the SAME base, which a relocated second load would not reproduce. Relocations are kept, so a
  # base that is genuinely occupied still loads (and the test asserts the bases matched rather than proving nothing).
  add_library(dmk_rtti_generation_fixture SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/rtti_generation_fixture.cpp"
  )
  set_target_properties(dmk_rtti_generation_fixture PROPERTIES PREFIX "" OUTPUT_NAME "dmk_rtti_generation_fixture")
  target_include_directories(dmk_rtti_generation_fixture PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
  dmk_static_runtime(dmk_rtti_generation_fixture SHARED)

  if(MSVC)
    target_link_options(dmk_rtti_generation_fixture PRIVATE /BASE:0x190000000 /DYNAMICBASE:NO)
  else()
    target_link_options(dmk_rtti_generation_fixture PRIVATE
      -Wl,--image-base,0x190000000 -Wl,--disable-dynamicbase)
  endif()

  # Both variants land next to the test executable, which is on the module search path. Test presets use
  # single-configuration Ninja; keep the standard per-configuration subdirectory for multi-config generators too.
  if(CMAKE_CONFIGURATION_TYPES)
    set(_dmk_rtti_fixture_output_dir "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
  else()
    set(_dmk_rtti_fixture_output_dir "${CMAKE_CURRENT_BINARY_DIR}")
  endif()
  set(_dmk_rtti_fixture_script "${PROJECT_SOURCE_DIR}/scripts/prepare_rtti_generation_fixtures.py")
  set(_dmk_rtti_fixture_a "${_dmk_rtti_fixture_output_dir}/dmk_rtti_gen_a.dll")
  set(_dmk_rtti_fixture_b "${_dmk_rtti_fixture_output_dir}/dmk_rtti_gen_b.dll")

  # The generation proofs cannot run without these files, so a missing interpreter is a configure error rather than a
  # delayed five-case runtime failure. LINK_DEPENDS reruns the post-link generator when its script changes, while
  # BYPRODUCTS lets Ninja rebuild a deleted variant and remove both variants during clean.
  find_program(DMK_PYTHON_EXECUTABLE NAMES python3 python REQUIRED)
  set_property(TARGET dmk_rtti_generation_fixture APPEND PROPERTY LINK_DEPENDS "${_dmk_rtti_fixture_script}")
  add_custom_command(TARGET dmk_rtti_generation_fixture POST_BUILD
    BYPRODUCTS "${_dmk_rtti_fixture_a}" "${_dmk_rtti_fixture_b}"
    COMMAND "${DMK_PYTHON_EXECUTABLE}"
            "${_dmk_rtti_fixture_script}"
            --input "$<TARGET_FILE:dmk_rtti_generation_fixture>"
            --variant-a "${_dmk_rtti_fixture_a}"
            --variant-b "${_dmk_rtti_fixture_b}"
            --type-name-a ".?AVDmkRttiGenerationFixtureA@@"
            --type-name-b ".?AVDmkRttiGenerationFixtureB@@"
    COMMENT "Producing the same-base RTTI generation fixture variants"
    VERBATIM)

  # CONFIGURE_DEPENDS triggers regeneration when the unit-test source set changes.
  file(GLOB TEST_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
  )
  list(SORT TEST_SOURCES)

  # psapi serves the cross-module hook tests; other Win32 dependencies propagate from DetourModKit.
  dmk_add_gtest_proof(
    TARGET DetourModKit_tests
    SOURCES ${TEST_SOURCES}
    LINK psapi
    INCLUDE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src
    SYSTEM_INCLUDE ${PROJECT_SOURCE_DIR}/external/simpleini ${DIRECTXMATH_INCLUDE_DIR}
    DEPENDS hook_target_lib dmk_rtti_generation_fixture
    LABELS "unit")

  # The lifecycle/cache-race proofs drive the DMK_ENABLE_TEST_SEAMS-gated seams compiled into the library above; the
  # test TU needs the same gate active to reference them. Only ever set in a test build.
  target_compile_definitions(DetourModKit_tests PRIVATE DMK_ENABLE_TEST_SEAMS)

  # Hook scenarios require distinct target addresses because some intentionally retain their patch for process life.
  # MSVC Release folds identical functions by default, so disable folding for this proof executable.
  if(MSVC)
    target_link_options(DetourModKit_tests PRIVATE /OPT:NOICF)
  endif()

  # The integration tests load the fixture from the test executable's directory.
  add_custom_command(TARGET hook_target_lib POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hook_target_lib>
      $<TARGET_FILE_DIR:DetourModKit_tests>
  )

  # Register the header-hygiene script's comment-stripper self-test as a ctest. The gate's legacy-token and backend
  # checks only inspect real code because check_header_hygiene.py blanks comments before scanning, so a regression in
  # its stripper (for example mistracking a C++14 digit separator as a char literal) would silently feed unstripped
  # prose to those checks and could fail a PR on a legacy spelling that appears only in a comment. This standalone
  # Python test pins the stripper behavior. The RTTI generation fixture above already makes Python a tests-ON
  # configure prerequisite, so every configured test tree registers the script self-tests below.
  add_test(NAME HeaderHygieneStripperSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_header_hygiene.py")
  set_tests_properties(HeaderHygieneStripperSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME EmitTlsCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_emit_tls.py")
  set_tests_properties(EmitTlsCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME ExportEqualityGateSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_export_equality.py")
  set_tests_properties(ExportEqualityGateSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME MechanicalStyleCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_mechanical_style.py")
  set_tests_properties(MechanicalStyleCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME NoTestSeamsCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_no_test_seams.py")
  set_tests_properties(NoTestSeamsCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME TestLabelInventoryGateSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_test_label_inventory.py")
  set_tests_properties(TestLabelInventoryGateSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME LifecycleSoakRestorationSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_run_lifecycle_soak.py")
  set_tests_properties(LifecycleSoakRestorationSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  # The benchmark result parser decides whether a benchmark run counts as evidence, so its refusals -- truncated
  # suite, spliced capture, self-contradicting record, vanished required gate -- are pinned here. Without this a
  # parser that silently accepted everything would make the release benchmark route green by construction.
  add_test(NAME BenchmarkResultsCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_benchmark_results.py"
            --ledger-probe "$<TARGET_FILE:dmk_bench_gate_probe>")
  set_tests_properties(BenchmarkResultsCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  # The workflow topology gate is what keeps the required routes required: an advisory marker restored on the format,
  # tidy or SIMD job, a required step that stopped being the reviewed program, or a release preflight that regained
  # the ability to publish, must fail a PR rather than a release. The self-test is the mutation matrix; the
  # repository run below is the positive control that the two together are not vacuous.
  add_test(NAME WorkflowTopologyCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_workflow_topology.py")
  set_tests_properties(WorkflowTopologyCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME WorkflowTopologyIsBlocking
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_workflow_topology.py"
            --repository-root "${PROJECT_SOURCE_DIR}")
  set_tests_properties(WorkflowTopologyIsBlocking PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")

  # The runtime identity boundary. The workflows bind contexts through an exact step environment and run one
  # exactly reviewed quoted command whose status decides the job, so the helper's own refusals are proved here
  # rather than only at dispatch time, where a wrong verdict would already have tagged or published. The second
  # route is a live negative control: it runs the real command line on a mismatched pair and requires a nonzero
  # exit, so a helper that degraded into accepting everything fails a build instead of waving a release through.
  add_test(NAME ReleaseIdentityCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_release_identity.py")
  set_tests_properties(ReleaseIdentityCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  add_test(NAME ReleaseIdentityRefusesAMismatchedCandidate
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_release_identity.py"
            --expected-sha 1111111111111111111111111111111111111111
            --event-sha 2222222222222222222222222222222222222222)
  set_tests_properties(ReleaseIdentityRefusesAMismatchedCandidate PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}" WILL_FAIL TRUE)
  add_test(NAME GTestExecutionCheckerSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_gtest_execution.py")
  set_tests_properties(GTestExecutionCheckerSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")

  # The same-base replacement case is host-conditional: it skips when the loader will not place both fixture variants
  # at the reserved base, and a skip counts as green. These two tests turn "it ran" into evidence rather than an
  # assumption -- the first writes the GoogleTest XML record, the second reads back the property the case publishes
  # only after observing the replacement extent. SKIP_RETURN_CODE keeps an unqualified developer host honest (Skipped,
  # not passed); release preflight runs the same checker WITHOUT --skip-exit-code, where a skip is a red candidate.
  set(_dmk_same_base_case
    "MemoryTest.ModuleRangeFor_CompletedSameBaseReplacementReportsTheReplacementExtent")
  set(_dmk_same_base_report "${CMAKE_BINARY_DIR}/dmk_same_base_replacement.xml")
  add_test(NAME SameBaseReplacementExecutionRecord
    COMMAND DetourModKit_tests "--gtest_filter=${_dmk_same_base_case}"
            "--gtest_output=xml:${_dmk_same_base_report}")
  set_tests_properties(SameBaseReplacementExecutionRecord PROPERTIES LABELS "unit"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}" FIXTURES_SETUP dmk_same_base_record)
  add_test(NAME SameBaseReplacementExecutionEvidence
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_gtest_execution.py"
            "${_dmk_same_base_report}"
            --case "${_dmk_same_base_case}"
            --property dmk_same_base_replacement=executed
            --skip-exit-code 77)
  set_tests_properties(SameBaseReplacementExecutionEvidence PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}" SKIP_RETURN_CODE 77 FIXTURES_REQUIRED dmk_same_base_record)

  # The three proof wrappers cannot share code with each other, so the compiler-runtime resolution they all depend on
  # lives in one script and is pinned here instead of drifting into three separately-wrong copies.
  add_test(NAME RuntimeDirResolverSelfTest
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_resolve_runtime_dir.py")
  set_tests_properties(RuntimeDirResolverSelfTest PROPERTIES LABELS "script-lint"
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")

  # Which TLS mechanism the dispatcher, input-delivery marker, and routed backend compiled to is not readable from the
  # source: on this toolchain thread_local, namespace-scope thread_local and __thread all lower to
  # __emutls_get_address, while __declspec(thread) is ignored with a warning and silently degrades to a shared global.
  # Only the emitted symbols distinguish them, so the gate reads both built archives. MinGW-gated because emutls is a
  # GCC lowering and nm reads its archives; the MSVC control is that no such lowering exists there, covered by
  # in-process proofs instead.
  if(DMK_PYTHON_EXECUTABLE AND MINGW)
    add_test(NAME EmitPathHasNoEmulatedTls
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_emit_tls.py"
              "$<TARGET_FILE:DetourModKit>" "$<TARGET_FILE:safetyhook>" --nm "${CMAKE_NM}")
    set_tests_properties(EmitPathHasNoEmulatedTls PROPERTIES LABELS "script-lint"
      TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}")
  endif()

  add_subdirectory(fault)
  add_subdirectory(lifecycle)

  # Freeze the lifecycle-proof names outside the lifecycle directory. The gate rejects missing or duplicate cases.
  set(lifecycle_proof_cases
    Lifecycle.StaticHookCannotOutliveLedgerState
    Lifecycle.TrapRetriesClosedWindowExecuteFault
    Lifecycle.TrapRetirementSerializesLateTransaction
    Lifecycle.LoggerFirstUseOomFailsClosed
    Lifecycle.LoggerConcurrentFirstUseOomFailsClosed
    Lifecycle.LoggerFirstUseSuccessCreatesLiveSink
    Lifecycle.LoggerPersistentBatchOomStillDrainsAndJoins
    Lifecycle.LoggerOversizeBatchSizeStillDrainsAndJoins
    Lifecycle.HookLedgerIsPerLinkedInstance
    Lifecycle.HookLedgerRefusesSameKitDuplicate
    Lifecycle.HookLedgerIsBlindAcrossLinkedInstances
    Lifecycle.ArmedForeignHookIsRefusedByDecode
    Lifecycle.HookRefusalCodesDistinguishTheMechanism
    Lifecycle.CrossBindingReleaseHasNoABBA
    Lifecycle.RetiredPressCallableDisposalHasNoSelfDeadlock
    Lifecycle.RetiredHoldCallableDisposalHasNoSelfDeadlock
    InputLifecycleProof.CrossGateHoldTeardownSurvivesSimultaneousStoreFailure
    InputLifecycleProof.CrossGateHoldRetirementSurvivesSimultaneousStoreFailure
    InputLifecycleProof.CrossGatePressDisposalSurvivesSimultaneousStoreFailure
    InputLifecycleProof.AbandonedParkedCallbackRunsDownBeforeClearing
    Lifecycle.InputGateProofRejectsAnUnknownScenario
    Lifecycle.DispatcherSubscribeCopiesNoCallableUnderLock
    Lifecycle.DispatcherCompactCopiesNoCallableUnderLock
    Lifecycle.DispatcherClearDestroysNoCallableUnderLock
    Lifecycle.DispatcherResetDestroysNoCallableUnderLock
    Lifecycle.DispatchCowProofRejectsAnUnknownScenario
    InputLifecycleProof.TlsExhaustionRefusesUntrackedDelivery
    InputLifecycleProof.TrackedDeliveryIsAdmitted
    InputLifecycleProof.TlsStoreFailureRefusesUntrackedDelivery
    InputLifecycleProof.AbandonedFacadeDrivePremiseRunsDownBeforeClearing
    InputLifecycleProof.TlsExhaustionProofRejectsAnUnknownScenario
    Lifecycle.ReloadServicerSelfRetiresThroughReaper
    Lifecycle.InputCallbackSelfShutdownDoesNotJoinSelf
    Lifecycle.InputRegistrationRacesCallbackShutdown
    Lifecycle.InputExternalShutdownRunsDownSynchronously
    InputLifecycleProof.AbandonedSelfShutdownPremiseRunsDownBeforeClearing
    Lifecycle.InputFirstUseOomFailsClosed
    Lifecycle.InputConcurrentFirstUseOomFailsClosed
    Lifecycle.InputFirstUseSuccessStartsEngine
    Lifecycle.XInputTimeoutRetainsTrampolinesWithoutAllocating
    Lifecycle.XInputPreBodyRouteRetainsExecutableChain
    Lifecycle.XInputActivePairSurvivesProcessExitStaticDestruction
    Lifecycle.XInputCleanReleaseNeedsNoAllocation
    Lifecycle.XInputDrainedTeardownBalancesModuleReferences
    Lifecycle.XInputFirstInstallOomFailsClosed
    Lifecycle.XInputFirstInstallCreateOomFailsClosed
    Lifecycle.XInputEnableBeforeMutationExceptionIsContained
    Lifecycle.XInputEnableAfterMutationExceptionIsReconciled
    Lifecycle.XInputDisableBeforeMutationExceptionRetainsChain
    Lifecycle.XInputDisableAfterMutationExceptionReconcilesOriginal
    Lifecycle.XInputExDisableExceptionRetainsPrimary
    Lifecycle.XInputPrimaryDisableExceptionCompensatesThePair
    Lifecycle.XInputInstallRecoversTheRetainedExMember
    Lifecycle.XInputNewerLayerSurvivesRawTeardown
    Lifecycle.XInputNewerLayerRetainsExPair
    Lifecycle.XInputCommittedArmInversionRetainsTrampoline
    Lifecycle.XInputUnownedExportDoesNotStrandThePair
    Lifecycle.XInputPrimaryLostDuringExArmDegradesThePair
    Lifecycle.XInputInstalledPairMaintenanceRecoversALostPrimary
    Lifecycle.XInputRetainedPairRecoversALostPrimary
    Lifecycle.XInputPollLoopMaintainsAPublishedPair
    Lifecycle.RoutedWrapperIsUnwindable
    Lifecycle.RoutedWrapperPropagatesNativeExceptions
    Lifecycle.RefusedUnwindRegistrationRollsBack
    Lifecycle.PublishedRouteMetadataIsRetained
    Lifecycle.RouteCapacityRefusesBeforePublication
    Lifecycle.XInputPairReservesCapacityAtomically
    Lifecycle.RefusedUnwindUnregistrationRetainsStorage
    Lifecycle.RouteCapacityOverflowRefusesCleanly
    Lifecycle.RouteRestoreFailureChargesPublication
    Lifecycle.RouteAllocatorReclaimsWholeBlock
    Lifecycle.MidRouteAccountingIncludesGeneratedStub
    Lifecycle.XInputForwardedExOrdinalIsHooked
    Lifecycle.XInputSameModuleExOrdinalIsHooked
    Lifecycle.XInputAbsentExOrdinalIsCompleteCoverage
    Lifecycle.XInputAliasedExOrdinalIsCompleteCoverage
    Lifecycle.ProfilerLateScopedProfileNoUAF
    Lifecycle.ProfilerFirstUseOomFailsClosed
    Lifecycle.ProfilerConcurrentFirstUseOomFailsClosed
    Lifecycle.ProfilerFirstUseSuccessPublishesFullRing
    DiagnosticsLifecycleProof.LatePinnedEmitterCannotTouchDestroyedState
    DiagnosticsLifecycleProof.PoisonedModuleLoadReportsExactZeroPopulation
    Lifecycle.BootstrapWorkerStaysMapped
    Lifecycle.BootstrapAttachPerformsNoHeapSetup
    Lifecycle.BootstrapWorkerDrainedUnloads
    Lifecycle.BootstrapBareFreeLibrarySelfDrains
    Lifecycle.BootstrapProcessExitWithLiveWorker
    Lifecycle.DetachAfterDrainRevokesBlockingAuthorization
    Lifecycle.ReloadServicerProcessExitNeverWaitsOnOwnedMutex
    Lifecycle.InputLoaderDetachRetainsCompleteOwner
    Lifecycle.FullLifecycleCycles
    Lifecycle.FullLifecycleConcurrent
    Lifecycle.FullLifecycleMisuse
    Lifecycle.FullLifecycleExit
    Lifecycle.LogicDllDrainReleasesEveryStagedCallable
    Lifecycle.LogicDllRetainedGuardCannotKeepCallableAlive
    Lifecycle.LogicDllHeldBindingIsBalancedByTheDrain
    Lifecycle.LogicDllParkedInputCallbackRefusesUnload
    Lifecycle.LogicDllParkedConfigSetterRefusesUnload
    Lifecycle.LogicDllParkedConfigCallbackRefusesUnload
    Lifecycle.LogicDllMidTeardownWaitsForParkedCallback
    Lifecycle.LogicDllMidPreAdapterRouteDrainsBeforeUnload
    Lifecycle.LogicDllMidPostAdapterRouteDrainsBeforeUnload
    Lifecycle.LogicDllPinnedMidStubStaysInertAfterUnload
    Lifecycle.LogicDllInlineCallerQuiescenceAllowsUnload)
  set(lifecycle_inventory_command
    "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_test_label_inventory.py"
    --build-directory "${CMAKE_BINARY_DIR}"
    --label lifecycle-proof
    --minimum 106)
  foreach(lifecycle_proof_case IN LISTS lifecycle_proof_cases)
    list(APPEND lifecycle_inventory_command --require "${lifecycle_proof_case}")
  endforeach()
  add_test(NAME Lifecycle.LabelInventoryIsComplete COMMAND ${lifecycle_inventory_command})
  set_tests_properties(Lifecycle.LabelInventoryIsComplete PROPERTIES
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}"
    LABELS "lifecycle-proof")

  # Declared here rather than in tests/fault/ on purpose: a gate that a skipped subdirectory can also skip proves
  # nothing about that subdirectory. `ctest -L fault-proof` reports success on an empty selection, so without this the
  # states that remove the fault coverage entirely -- a toolchain gate around the subdirectory, a renamed case, a proof
  # host that was never registered -- all read as green. The names are spelled out so the expectation is greppable and
  # a rename is a reviewable diff on both sides.
  add_test(NAME FaultProof.LabelInventoryIsComplete
    COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_test_label_inventory.py"
            --build-directory "${CMAKE_BINARY_DIR}"
            --label "fault-proof"
            --minimum 13
            --expect-target fault_tests
            --require FaultContainment.GuardedReadFromNoAccessPageFailsClosed
            --require FaultContainment.GuardedWalkThroughNoAccessHopFailsClosed
            --require FaultContainment.WriteInPlaceToNoAccessTargetFailsClosed
            --require FaultContainment.WriteBytesEscalatesThroughReadOnlyTargetAndRestores
            --require FaultContainment.RipSnapshotTailFaultAtPageBoundaryFailsClosed
            --require FaultContainment.GuardedRegionStaysArmedAcrossANestedGuardedRead
            --require FastStringStraddle.BlockedFirstByteReportsNotWrittenAndCommitsNoTailByte
            --require FastStringStraddle.MidSpanSeamReportsMayBePartialWithTheFullPrefixCommitted
            --require FaultProof.RegionSweepDoesNotSwallowAnOutOfSpanFault
            --require FaultProof.NarrowWindowSweepDoesNotSwallowAnOutOfSpanFault
            --require FaultProof.NarrowWindowSweepContainsAnInSpanFault
            --require FaultProof.ScannerEscapeProbeRejectsAnUnknownScenario)
  set_tests_properties(FaultProof.LabelInventoryIsComplete PROPERTIES
    TIMEOUT "${DMK_TEST_TIMEOUT_SECONDS}"
    LABELS "fault-proof")
endif()

if(DMK_BUILD_BENCHMARKS)
  # Standalone microbench executables. Deliberately do NOT link gtest --
  # the benchmarks are raw main()s that print a TSV table to stdout, so
  # they can run under any build configuration without the gtest runtime.
  add_executable(DetourModKit_bench
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_event_dispatcher.cpp"
  )

  target_link_libraries(DetourModKit_bench PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench PRIVATE
    ${PROJECT_SOURCE_DIR}/include
  )

  add_executable(DetourModKit_bench_scanner
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_scanner.cpp"
  )

  target_link_libraries(DetourModKit_bench_scanner PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench_scanner PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
  )

  if(DMK_ENABLE_AVX512)
    target_compile_definitions(DetourModKit_bench_scanner PRIVATE DMK_BENCH_BUILD_ROLE="AVX512")
  else()
    target_compile_definitions(DetourModKit_bench_scanner PRIVATE DMK_BENCH_BUILD_ROLE="AVX2")
  endif()

  add_executable(DetourModKit_bench_memory
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_memory.cpp"
  )

  target_link_libraries(DetourModKit_bench_memory PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench_memory PRIVATE
    ${PROJECT_SOURCE_DIR}/include
  )

  add_executable(DetourModKit_bench_logger
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_logger.cpp"
  )

  target_link_libraries(DetourModKit_bench_logger PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench_logger PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
  )

  # Runtime footprint measurement (P2-4): logger/profiler high-water and resident bytes per linked instance.
  add_executable(DetourModKit_bench_footprint
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_footprint.cpp"
  )

  target_link_libraries(DetourModKit_bench_footprint PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench_footprint PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
  )

  # Signature-health corpus report (P1-9, T-SIGHEALTH-CORPUS): estimate-vs-ground-truth over real x64 .text.
  add_executable(DetourModKit_corpus_sighealth
    "${CMAKE_CURRENT_SOURCE_DIR}/corpus_sighealth.cpp"
  )

  target_link_libraries(DetourModKit_corpus_sighealth PRIVATE DetourModKit)

  target_include_directories(DetourModKit_corpus_sighealth PRIVATE
    ${PROJECT_SOURCE_DIR}/include
  )

  # Benchmark drivers must supply the gcov runtime when they consume an instrumented archive.
  foreach(_bench DetourModKit_bench DetourModKit_bench_scanner DetourModKit_bench_memory DetourModKit_bench_logger
    DetourModKit_bench_footprint DetourModKit_corpus_sighealth)
    target_link_libraries(${_bench} PRIVATE dmk_coverage)
  endforeach()

  # Match each bench's LTO state to the library's so a bench and the archive it links form ONE LTO unit -- never a mixed
  # link. A mixed link fails both ways: a non-LTO bench object against an LTO-only archive makes GCC's linker plugin
  # re-emit libstdc++'s C++20-constrained std::thread/std::tuple linkonce symbol twice (spurious multiple-definition),
  # and an LTO bench against a non-LTO archive is the symmetric hazard. Read the library's single LTO decision
  # (_dmk_apply_lto, resolved once in the top-level CMakeLists.txt before this subdirectory is added) rather than
  # re-deriving the condition here, so the bench and the archive can never drift out of one LTO state on any
  # toolchain --
  # including the GCC major where the library forces LTO off because that lto1 mis-links LTO archives.
  if(_dmk_apply_lto)
    set_target_properties(DetourModKit_bench DetourModKit_bench_scanner DetourModKit_bench_memory
      DetourModKit_bench_logger DetourModKit_bench_footprint DetourModKit_corpus_sighealth
      PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  endif()
endif()
