# Invoked as:
#   cmake -DCTEST_EXE=<ctest> -DPROBE=<hung-probe-exe> -DSCRATCH=<dir>
#     [-DINNER_TIMEOUT=<s>] -P verify_ctest_timeout.cmake

if(NOT CTEST_EXE OR NOT PROBE OR NOT SCRATCH)
  message(FATAL_ERROR "verify_ctest_timeout: CTEST_EXE, PROBE, and SCRATCH are all required")
endif()

if(NOT DEFINED INNER_TIMEOUT)
  set(INNER_TIMEOUT 2)
endif()

file(MAKE_DIRECTORY "${SCRATCH}")

# Bracket arguments preserve backslashes in Windows paths.
file(WRITE "${SCRATCH}/CTestTestfile.cmake"
  "add_test([=[HungProbe]=] [=[${PROBE}]=])\n"
  "set_tests_properties([=[HungProbe]=] PROPERTIES TIMEOUT ${INNER_TIMEOUT})\n")

execute_process(
  COMMAND "${CTEST_EXE}" --test-dir "${SCRATCH}" --output-on-failure
  RESULT_VARIABLE _rc
  OUTPUT_VARIABLE _out
  ERROR_VARIABLE _err
  TIMEOUT 90)

set(_combined "${_out}${_err}")

# A nonzero result alone could also mean a crash or missing executable.
if(_rc EQUAL 0)
  message(FATAL_ERROR
    "CTest timeout control FAILED: expected a nonzero ctest result from the hung probe but got 0.\n${_combined}")
endif()

# The status prefix prevents the scratch path from satisfying a bare "timeout" match.
string(TOLOWER "${_combined}" _lower)

if(NOT _lower MATCHES "\\*\\*\\*timeout")
  message(FATAL_ERROR
    "CTest timeout control FAILED: ctest failed (rc=${_rc}) but its output carries no '***Timeout' status, so the "
    "failure was not the execution timeout being enforced (a missing or crashed probe fails exactly this way).\n"
    "${_combined}")
endif()

message(STATUS "CTest timeout control OK: the hung probe was killed by TIMEOUT enforcement (rc=${_rc}).")
