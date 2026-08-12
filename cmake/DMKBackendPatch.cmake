# The external/safetyhook submodule is pinned to a commit the configured upstream remote serves
# (cursey/safetyhook main, f44cc07), so `git submodule update --init` resolves it on a fresh clone.
# DMK's backend fixes -- trap-transaction status reporting, post-static-destruction teardown, and
# commit-truthful and witness-reconciled enabled state with emitted-patch provenance and test-only transaction seams --
# exist on no upstream ref, so they are carried in-tree as reviewable patch files under
# cmake/safetyhook_patches/ and re-applied to the submodule working tree at configure time. Applying
# the pinned base plus these patches reproduces the reviewed backend tree byte for byte. When the fixes
# land upstream the pin moves to that commit and this module plus the patch directory are deleted.
# See AGENTS.md [B-01] and the rollout plan's "Backend submodule sourcing" release gate.

# Apply each patch in cmake/safetyhook_patches/ to the SafetyHook submodule, in filename order.
# Idempotent: a patch already present is detected by a clean reverse-apply and skipped, so repeated
# configures of one build tree do not double-apply. Fails closed: a submodule at an unexpected commit
# (a patch that neither applies nor is already present) aborts configure rather than silently building
# an un-patched backend that would drop the fixes these patches exist to carry.
#
# Each patch here MUST be an independent net delta from the pinned base, not a step in a dependent
# chain. `git apply --check` validates a patch against the on-disk tree as it currently is; it does
# not stage one patch's result before checking the next, so it cannot verify a chain where patch N
# depends on patch N-1, and a chain also makes a later patch un-reverse-checkable once an earlier one
# has rewritten its context. The DMK backend delta is therefore carried as a single squashed patch
# (every fix, regenerable via `git -C external/safetyhook diff <base> <reviewed>`).
# Decide, immediately after the apply loop, that the working tree the build is about to compile is exactly the
# reviewed patch output: every file the patch writes is changed, no other tracked file is, nothing is staged, ordinary
# untracked content is only the owned lock, and ignored content stays under frozen non-source output roots. git is the
# whole toolbox at configure time, so this rules on the changed-file SET; scripts/check_backend_patch.py additionally
# reconstructs each file byte for byte in the blocking quality route. Fails configure rather than building a backend
# nobody reviewed.
function(dmk_backend_ignored_output_allowed path result)
  string(REPLACE "\\" "/" _normalized "${path}")
  string(REGEX REPLACE "/+$" "" _normalized "${_normalized}")
  if(_normalized MATCHES "^(build|build32|__build|amalgamated-dist)(/|$)"
     OR _normalized MATCHES "^cmake-build[^/]*(/|$)"
     OR _normalized MATCHES "^\\.(idea|vscode|vs)(/|$)"
     OR _normalized MATCHES "^docs/(html|latex)(/|$)"
     OR _normalized STREQUAL "docs/Doxyfile")
    set(${result} TRUE PARENT_SCOPE)
  else()
    set(${result} FALSE PARENT_SCOPE)
  endif()
endfunction()

function(dmk_verify_backend_state submodule_dir patches)
  set(_expected "")
  foreach(_patch IN LISTS patches)
    file(STRINGS "${_patch}" _headers REGEX "^diff --git a/.+ b/.+$")
    foreach(_header IN LISTS _headers)
      string(REGEX REPLACE "^diff --git a/.+ b/(.+)$" "\\1" _target "${_header}")
      list(APPEND _expected "${_target}")
    endforeach()
  endforeach()
  list(REMOVE_DUPLICATES _expected)

  if(NOT _expected)
    message(FATAL_ERROR
      "No 'diff --git' file headers in the vendored SafetyHook patches, so the configured backend state cannot be "
      "decided. The patch set must be a git-formatted diff.")
  endif()

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" ls-files -v
    WORKING_DIRECTORY "${submodule_dir}"
    OUTPUT_VARIABLE _visibility
    ERROR_VARIABLE _visibility_error
    RESULT_VARIABLE _visibility_rc
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _visibility_rc EQUAL 0)
    message(FATAL_ERROR "Could not read '${submodule_dir}' tracked-path visibility flags: ${_visibility_error}")
  endif()

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" status --porcelain=v1 -uall --ignored=matching
    WORKING_DIRECTORY "${submodule_dir}"
    OUTPUT_VARIABLE _status
    ERROR_VARIABLE _status_error
    RESULT_VARIABLE _status_rc
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _status_rc EQUAL 0)
    message(FATAL_ERROR "Could not read '${submodule_dir}' backend state: ${_status_error}")
  endif()

  string(REGEX REPLACE "\r?\n" ";" _entries "${_status}")
  set(_changed "")
  set(_problems "")
  string(REGEX REPLACE "\r?\n" ";" _visibility_entries "${_visibility}")
  foreach(_entry IN LISTS _visibility_entries)
    if(_entry STREQUAL "")
      continue()
    endif()
    string(LENGTH "${_entry}" _entry_length)
    if(_entry_length LESS 2)
      list(APPEND _problems "malformed tracked-path visibility entry '${_entry}'")
      continue()
    endif()
    string(SUBSTRING "${_entry}" 0 1 _visibility_tag)
    if(_visibility_tag MATCHES "^[a-z]$" OR _visibility_tag STREQUAL "S")
      string(SUBSTRING "${_entry}" 2 -1 _entry_path)
      list(APPEND _problems
        "tracked path carries an assume-unchanged or skip-worktree visibility flag: '${_entry_path}'")
    endif()
  endforeach()

  foreach(_entry IN LISTS _entries)
    if(_entry STREQUAL "")
      continue()
    endif()
    string(SUBSTRING "${_entry}" 0 2 _entry_state)
    string(SUBSTRING "${_entry}" 3 -1 _entry_path)
    if(_entry_state STREQUAL "??")
      if(NOT _entry_path STREQUAL ".dmk_patch.lock")
        list(APPEND _problems "untracked content '${_entry_path}'")
      endif()
    elseif(_entry_state STREQUAL "!!")
      dmk_backend_ignored_output_allowed("${_entry_path}" _ignored_allowed)
      if(NOT _entry_path STREQUAL ".dmk_patch.lock" AND NOT _ignored_allowed)
        list(APPEND _problems "ignored content outside reviewed generated-output roots: '${_entry_path}'")
      endif()
    else()
      string(SUBSTRING "${_entry_state}" 0 1 _index_state)
      if(NOT _index_state STREQUAL " ")
        list(APPEND _problems "staged content '${_entry_path}'")
      endif()
      list(APPEND _changed "${_entry_path}")
    endif()
  endforeach()

  foreach(_entry_path IN LISTS _changed)
    if(NOT _entry_path IN_LIST _expected)
      list(APPEND _problems "tracked edit outside the vendored patch: '${_entry_path}'")
    endif()
  endforeach()
  foreach(_target IN LISTS _expected)
    if(NOT _target IN_LIST _changed)
      list(APPEND _problems "'${_target}' is unchanged although the vendored patch writes it")
    endif()
  endforeach()

  if(_problems)
    string(REPLACE ";" "\n  " _report "${_problems}")
    message(FATAL_ERROR
      "The configured SafetyHook backend is not exactly the reviewed patch output:\n  ${_report}\n"
      "Reset it and reconfigure:\n"
      "  git submodule update --init --force external/safetyhook")
  endif()
endfunction()

function(dmk_apply_backend_patches submodule_dir patch_dir)
  find_package(Git REQUIRED) # a fresh clone already needs git for `submodule update`

  # CONFIGURE_DEPENDS re-globs when the patch directory changes, and is rejected outright in script mode, which has no
  # configure to re-run.
  if(CMAKE_SCRIPT_MODE_FILE)
    file(GLOB _patches LIST_DIRECTORIES false "${patch_dir}/*.patch")
  else()
    file(GLOB _patches LIST_DIRECTORIES false CONFIGURE_DEPENDS "${patch_dir}/*.patch")
  endif()
  list(SORT _patches) # deterministic order; each patch is an independent net delta (see above)

  if(NOT _patches)
    message(FATAL_ERROR
      "No backend patches found in '${patch_dir}'. The vendored SafetyHook fixes would be dropped and "
      "the backend would build without the trap-transaction and static-teardown corrections. Restore "
      "cmake/safetyhook_patches/ from version control.")
  endif()

  # Serialize the sequence across concurrent configures that share this submodule checkout (two presets configured
  # in parallel against one source tree): an interleaved apply could half-patch the tree or spuriously fail a
  # forward-check. The lock is submodule-specific, so independent checkouts never contend; the lock file is left in
  # the (already patch-dirty) submodule working tree by design. Released after the loop, or on process exit if a
  # patch aborts configure mid-sequence.
  set(_dmk_patch_lock "${submodule_dir}/.dmk_patch.lock")
  file(LOCK "${_dmk_patch_lock}" TIMEOUT 120 RESULT_VARIABLE _dmk_lock_rc)
  if(_dmk_lock_rc)
    message(FATAL_ERROR "Could not acquire the SafetyHook backend-patch lock '${_dmk_patch_lock}': ${_dmk_lock_rc}")
  endif()

  foreach(_patch IN LISTS _patches)
    get_filename_component(_name "${_patch}" NAME)

    # Already applied? A clean reverse-apply proves the patch's lines are present. Skip to stay idempotent.
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" apply --reverse --check -- "${_patch}"
      WORKING_DIRECTORY "${submodule_dir}"
      RESULT_VARIABLE _reverse_rc
      OUTPUT_QUIET ERROR_QUIET)
    if(_reverse_rc EQUAL 0)
      message(STATUS "SafetyHook backend patch already present, skipping: ${_name}")
      continue()
    endif()

    # Applies cleanly to the current (pinned) tree?
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" apply --check -- "${_patch}"
      WORKING_DIRECTORY "${submodule_dir}"
      RESULT_VARIABLE _forward_rc
      OUTPUT_QUIET ERROR_QUIET)
    if(NOT _forward_rc EQUAL 0)
      message(FATAL_ERROR
        "SafetyHook backend patch '${_name}' neither applies to nor is already present in\n"
        "  '${submodule_dir}'.\n"
        "The submodule is at an unexpected commit. Reset it to the pinned base and re-init:\n"
        "  git submodule update --init --force external/safetyhook")
    endif()

    execute_process(
      COMMAND "${GIT_EXECUTABLE}" apply -- "${_patch}"
      WORKING_DIRECTORY "${submodule_dir}"
      RESULT_VARIABLE _apply_rc
      OUTPUT_VARIABLE _apply_out
      ERROR_VARIABLE _apply_out)
    if(NOT _apply_rc EQUAL 0)
      message(FATAL_ERROR "SafetyHook backend patch '${_name}' passed --check but failed to apply:\n${_apply_out}")
    endif()
    message(STATUS "Applied vendored SafetyHook backend patch: ${_name}")
  endforeach()

  # Still under the lock: a concurrent configure mid-sequence would otherwise be read as a half-applied delta.
  dmk_verify_backend_state("${submodule_dir}" "${_patches}")

  file(LOCK "${_dmk_patch_lock}" RELEASE)
endfunction()

# Script-mode entry point:
#   cmake -DDMK_SUBMODULE_DIR=<dir> -DDMK_PATCH_DIR=<dir> -P cmake/DMKBackendPatch.cmake
# runs the same apply-and-verify sequence a configure runs, so a route with no compiler (the blocking backend-patch
# quality job) can prove that THIS module turns the pristine pin into the reviewed backend. CMAKE_SCRIPT_MODE_FILE is
# set only under -P, so an ordinary include() from the root CMakeLists never reaches it.
if(CMAKE_SCRIPT_MODE_FILE)
  if(NOT DEFINED DMK_SUBMODULE_DIR OR NOT DEFINED DMK_PATCH_DIR)
    message(FATAL_ERROR "Script mode requires nonempty DMK_SUBMODULE_DIR and DMK_PATCH_DIR.")
  endif()
  if("${DMK_SUBMODULE_DIR}" STREQUAL "" OR "${DMK_PATCH_DIR}" STREQUAL "")
    message(FATAL_ERROR "Script mode requires nonempty DMK_SUBMODULE_DIR and DMK_PATCH_DIR.")
  endif()
  dmk_apply_backend_patches("${DMK_SUBMODULE_DIR}" "${DMK_PATCH_DIR}")
endif()
