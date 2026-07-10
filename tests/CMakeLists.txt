cmake_minimum_required(VERSION 3.28)

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

  # Suppress warnings from GoogleTest sources
  foreach(_ext_target gtest gtest_main gmock gmock_main)
    if(TARGET ${_ext_target})
      target_compile_options(${_ext_target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-w>
        $<$<CXX_COMPILER_ID:MSVC>:/w>
      )
    endif()
  endforeach()

  # Test fixture DLL for cross-module hook integration tests
  add_library(hook_target_lib SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hook_target_lib.cpp"
  )
  set_target_properties(hook_target_lib PROPERTIES
    PREFIX ""
    OUTPUT_NAME "hook_target_lib"
  )

  # Automatically collect all test source files
  # This will include all test_*.cpp files and main.cpp
  file(GLOB TEST_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp"
  )

  # Sort the list for deterministic build order
  list(SORT TEST_SOURCES)

  message(STATUS "Discovered test files:")

  foreach(test_file ${TEST_SOURCES})
    message(STATUS "  - ${test_file}")
  endforeach()

  # Enable testing for the DetourModKit library
  add_executable(DetourModKit_tests ${TEST_SOURCES})

  # Ensure the hook target DLL is built before tests and placed alongside the test exe
  add_dependencies(DetourModKit_tests hook_target_lib)
  add_custom_command(TARGET hook_target_lib POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:hook_target_lib>
      $<TARGET_FILE_DIR:DetourModKit_tests>
  )

  # Link GoogleTest and DetourModKit.
  # psapi is needed by test_hook_integration.cpp (GetModuleInformation).
  # user32 and xinput1_4 propagate transitively from DetourModKit (INTERFACE).
  target_link_libraries(DetourModKit_tests
    PRIVATE
    DetourModKit
    GTest::gtest_main
    psapi
  )

  # Include directories
  target_include_directories(DetourModKit_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
  )

  # External dependency headers as SYSTEM to suppress their warnings
  target_include_directories(DetourModKit_tests SYSTEM PRIVATE
    ${PROJECT_SOURCE_DIR}/external/simpleini
    ${DIRECTXMATH_INCLUDE_DIR}
  )

  # The tests use ISO C file APIs (std::fopen) for temp-file fixtures; MSVC flags these as C4996 under /W4 /WX.
  # The shipped library uses none of them, so scope the deprecation opt-out to the test target only.
  target_compile_definitions(DetourModKit_tests PRIVATE $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)

  # Statically link the GCC runtime into the MinGW test binaries. The gtest PRE_TEST discovery launches the test
  # executable to enumerate cases, and a CI runner can resolve a different libstdc++ / libgcc / winpthread on PATH
  # than the toolchain that built it -- that launch then fails with STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139) before
  # any test runs. Embedding the runtime removes the external DLL dependency so discovery and the tests are
  # PATH-independent. These binaries are never shipped (the installed artifact is the static library archive).
  if(MINGW)
    target_link_options(DetourModKit_tests PRIVATE -static -static-libgcc -static-libstdc++)
    target_link_options(hook_target_lib PRIVATE -static-libgcc -static-libstdc++)
  endif()

  # Register tests with CTest. The statically-linked debug test binary is large (tens of MB) and enumerates ~1600
  # cases, so its first cold --gtest_list_tests launch can exceed the 5s default discovery timeout on a slow or
  # freshly-built disk; raise the budget so PRE_TEST discovery does not spuriously fail (CTest exit 8).
  include(GoogleTest)
  gtest_discover_tests(DetourModKit_tests DISCOVERY_MODE PRE_TEST DISCOVERY_TIMEOUT 120)

  # Optional: Add code coverage if requested
  option(DMK_ENABLE_COVERAGE "Enable code coverage reporting" OFF)

  if(DMK_ENABLE_COVERAGE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
      # Instrument both the library and the test executable for coverage
      target_compile_options(DetourModKit PRIVATE --coverage -fprofile-arcs -ftest-coverage)
      target_link_options(DetourModKit PRIVATE --coverage)
      target_compile_options(DetourModKit_tests PRIVATE --coverage -fprofile-arcs -ftest-coverage)
      target_link_options(DetourModKit_tests PRIVATE --coverage)
    endif()
  endif()

  # Standalone host-safety harnesses, registered as ctest tests. The fault-containment and lifecycle fixtures cannot
  # share a process with the rest of the suite: the fault fixtures hold a leaked PAGE_NOACCESS page, and the lifecycle
  # fixtures replace global operator new / delete and drive real DLL-loader and static-teardown events. Each is built
  # and run by its own standalone-link script against the prebuilt archive. Registering those scripts as ctest tests
  # lets `ctest` drive them in the normal flow rather than a bespoke workflow. Gated to a MinGW Debug tree: the scripts
  # compile with g++, exercise the MinGW vectored-handler paths, need a POSIX shell, and link the Debug archive (a
  # Release ctest leg would mix a -O0 fixture TU against the -O2 archive). They compile at test time, so they depend on
  # the archive already being built, which the normal build-then-test order guarantees.
  if(MINGW AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    find_program(DMK_BASH_EXECUTABLE NAMES bash)

    if(DMK_BASH_EXECUTABLE)
      add_test(NAME FaultContainmentStandalone
        COMMAND "${DMK_BASH_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/run_fault_tests.sh" "${CMAKE_BINARY_DIR}")
      add_test(NAME LifecycleHostSafetyStandalone
        COMMAND "${DMK_BASH_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/run_lifecycle_proofs.sh" "${CMAKE_BINARY_DIR}")
      # A shared label so a run can include or exclude the compile-at-test-time harnesses (ctest -L / -LE standalone-harness).
      set_tests_properties(FaultContainmentStandalone LifecycleHostSafetyStandalone PROPERTIES LABELS "standalone-harness")
    else()
      message(STATUS "bash not found; the fault / lifecycle standalone harnesses will not be registered with ctest.")
    endif()
  endif()

  # Register the header-hygiene script's comment-stripper self-test as a ctest. The gate's legacy-token and backend
  # checks only inspect real code because check_header_hygiene.py blanks comments before scanning, so a regression in
  # its stripper (for example mistracking a C++14 digit separator as a char literal) would silently feed unstripped
  # prose to those checks and could fail a PR on a legacy spelling that appears only in a comment. This standalone
  # Python test pins the stripper behavior. Gated on a discovered interpreter so a machine without Python simply skips
  # it, mirroring the bash-gated standalone harnesses above.
  find_program(DMK_PYTHON_EXECUTABLE NAMES python3 python)

  if(DMK_PYTHON_EXECUTABLE)
    add_test(NAME HeaderHygieneStripperSelfTest
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_header_hygiene.py")
    set_tests_properties(HeaderHygieneStripperSelfTest PROPERTIES LABELS "script-lint")
  else()
    message(STATUS "python not found; the header-hygiene stripper self-test will not be registered with ctest.")
  endif()
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

  add_executable(DetourModKit_bench_memory
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_memory.cpp"
  )

  target_link_libraries(DetourModKit_bench_memory PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench_memory PRIVATE
    ${PROJECT_SOURCE_DIR}/include
  )

  # Match each bench's LTO state to the library's so a bench and the archive it links form ONE LTO unit -- never a mixed
  # link. A mixed link fails both ways: a non-LTO bench object against an LTO-only archive makes GCC's linker plugin
  # re-emit libstdc++'s C++20-constrained std::thread/std::tuple linkonce symbol twice (spurious multiple-definition),
  # and an LTO bench against a non-LTO archive is the symmetric hazard. Read the library's single LTO decision
  # (_dmk_apply_lto, resolved once in the top-level CMakeLists.txt before this subdirectory is added) rather than
  # re-deriving the condition here, so the bench and the archive can never drift out of one LTO state on any toolchain --
  # including the GCC major where the library forces LTO off because that lto1 mis-links LTO archives.
  if(_dmk_apply_lto)
    set_target_properties(DetourModKit_bench DetourModKit_bench_scanner DetourModKit_bench_memory
      PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  endif()
endif()
