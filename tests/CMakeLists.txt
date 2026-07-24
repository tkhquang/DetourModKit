cmake_minimum_required(VERSION 3.28)

# Test and benchmark TUs include Win32 implementation headers directly; keep their macro policy local to this
# directory so it cannot reach an add_subdirectory or installed-package consumer. The package consumer projects
# configure standalone (never via add_subdirectory from here), and their windows_macro_probe TUs fail the build if
# NOMINMAX ever reaches a consumer compile line, so the directory-wide form cannot leak past the tests.
if(WIN32)
  add_compile_definitions(NOMINMAX)
endif()

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

  # A DLL cannot be fully static, but embedding the gcc and standard-library runtimes avoids mismatched copies on PATH.
  add_library(hook_target_lib SHARED
    "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/hook_target_lib.cpp"
  )
  set_target_properties(hook_target_lib PROPERTIES
    PREFIX ""
    OUTPUT_NAME "hook_target_lib"
  )
  dmk_static_runtime(hook_target_lib SHARED)

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
    DEPENDS hook_target_lib
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
  # Python test pins the stripper behavior. Gated on a discovered interpreter so a machine without Python simply skips
  # it, mirroring the discovered-tool gating the proof subdirectories use.
  find_program(DMK_PYTHON_EXECUTABLE NAMES python3 python)

  if(DMK_PYTHON_EXECUTABLE)
    add_test(NAME HeaderHygieneStripperSelfTest
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_header_hygiene.py")
    set_tests_properties(HeaderHygieneStripperSelfTest PROPERTIES LABELS "script-lint")
    add_test(NAME EmitTlsCheckerSelfTest
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_emit_tls.py")
    set_tests_properties(EmitTlsCheckerSelfTest PROPERTIES LABELS "script-lint")
    add_test(NAME ExportEqualityGateSelfTest
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_export_equality.py")
    set_tests_properties(ExportEqualityGateSelfTest PROPERTIES LABELS "script-lint")
    add_test(NAME MechanicalStyleCheckerSelfTest
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/test_check_mechanical_style.py")
    set_tests_properties(MechanicalStyleCheckerSelfTest PROPERTIES LABELS "script-lint")
  endif()

  # Which TLS mechanism the dispatcher's emit path compiled to is not readable from the source:
  # on this toolchain thread_local, namespace-scope thread_local and __thread all lower to __emutls_get_address, while
  # __declspec(thread) is ignored with a warning and silently degrades to a shared global. Only the emitted symbols
  # distinguish them, so the gate reads the built archive. MinGW-gated because emutls is a GCC lowering and nm reads
  # its archives; the MSVC control is that no such lowering exists there, covered by the in-process proofs instead.
  if(DMK_PYTHON_EXECUTABLE AND MINGW)
    add_test(NAME EmitPathHasNoEmulatedTls
      COMMAND "${DMK_PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_emit_tls.py"
              "$<TARGET_FILE:DetourModKit>" --nm "${CMAKE_NM}")
    set_tests_properties(EmitPathHasNoEmulatedTls PROPERTIES LABELS "script-lint")
  endif()

  if(NOT DMK_PYTHON_EXECUTABLE)
    message(STATUS "python not found; the header-hygiene stripper and emit-TLS self-tests will not be registered.")
  endif()

  add_subdirectory(fault)
  add_subdirectory(lifecycle)
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

  add_executable(DetourModKit_bench_logger
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_logger.cpp"
  )

  target_link_libraries(DetourModKit_bench_logger PRIVATE DetourModKit)

  target_include_directories(DetourModKit_bench_logger PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
  )

  # Benchmark drivers must supply the gcov runtime when they consume an instrumented archive.
  foreach(_bench DetourModKit_bench DetourModKit_bench_scanner DetourModKit_bench_memory DetourModKit_bench_logger)
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
      DetourModKit_bench_logger
      PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  endif()
endif()
