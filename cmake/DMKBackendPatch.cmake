# The external/safetyhook submodule is pinned to a commit the configured upstream remote serves (cursey/safetyhook main,
# f44cc07), so `git submodule update --init` resolves it on a fresh clone. DMK's backend fixes -- trap-transaction
# status reporting, post-static-destruction teardown, and commit-truthful and witness-reconciled enabled state with
# emitted-patch provenance and test-only transaction seams -- exist on no upstream ref, so they are carried in-tree as
# reviewable patch files under cmake/safetyhook_patches/ and re-applied to the submodule working tree at configure time.
# Applying the pinned base plus these patches reproduces the reviewed backend tree byte for byte. When the fixes land
# upstream the pin moves to that commit and this module plus the patch directory are deleted. See AGENTS.md [B-01] and
# the rollout plan's "Backend submodule sourcing" release gate.

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
# Decide, while holding the patch lock, that the checkout starts at the pinned commit and that the working tree the
# build is about to compile is exactly base plus patch: every owned target is reconstructed and compared, no other
# tracked file changed, nothing is staged, ordinary untracked content is only the lock, and ignored content stays under
# frozen non-source output roots. Fails configure rather than building a backend nobody reviewed.
# The membership tests below need CMP0057. An include() from the root CMakeLists inherits it from the project's
# cmake_minimum_required, but `cmake -P` starts a script with no project policy state, so on CMake 3.x every `IN_LIST`
# here fails with "Unknown arguments specified" instead of deciding the backend. Declared before the functions because
# a function captures the policy state where it is defined, not where it is called.
cmake_policy(SET CMP0057 NEW)

set(_DMK_BACKEND_BASE_COMMIT "f44cc070a8340f2f26649553c49533475417304d")

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

# Rebuild the reviewed output for `targets` -- pinned base blob plus the vendored patch -- in a scratch tree that is
# never the live checkout, then compare each target's bytes against what the build is about to compile. Appends one
# entry to `problems` per drifted target.
#
# The changed-path set alone cannot decide this. An extra edit INSIDE an already patched target leaves the set
# identical, and once the patch's own lines are present the idempotence reverse-apply stays clean too, so both earlier
# signals report green while configure compiles bytes nobody reviewed.
#
# Normalization is explicit: the patch is written LF before it is applied, and the comparison ignores a carriage return
# at end of line. That is the same fold scripts/check_backend_patch.py applies with lf(), so a checkout's line-ending
# policy cannot decide equality on either side of the shared model.
function(dmk_reconstruct_backend_targets submodule_dir patches targets base_commit problems_var)
  set(_problems "${${problems_var}}")

  # The scratch tree lives in the submodule's git directory, which is outside the working tree the state check
  # enumerates, so reconstruction can never be mistaken for backend content.
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse --absolute-git-dir
    WORKING_DIRECTORY "${submodule_dir}"
    OUTPUT_VARIABLE _git_dir
    RESULT_VARIABLE _git_dir_rc
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _git_dir_rc EQUAL 0 OR _git_dir STREQUAL "")
    list(APPEND _problems "could not locate the backend git directory, so byte equality cannot be decided")
    set(${problems_var} "${_problems}" PARENT_SCOPE)
    return()
  endif()

  set(_scratch "${_git_dir}/dmk-backend-reconstruct")
  file(REMOVE_RECURSE "${_scratch}")
  file(MAKE_DIRECTORY "${_scratch}/tree")

  # `git apply` resolves a patch's paths against the root of whatever repository it discovers, not against its working
  # directory. Without a repository of its own the scratch tree would inherit an enclosing one and the reconstruction
  # would be applied to real sources. Making the scratch tree its own root pins resolution to it wherever it sits.
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" init --quiet
    WORKING_DIRECTORY "${_scratch}/tree"
    RESULT_VARIABLE _scratch_init_rc
    OUTPUT_QUIET ERROR_QUIET)
  if(NOT _scratch_init_rc EQUAL 0)
    list(APPEND _problems "could not anchor the reconstruction tree, so byte equality cannot be decided")
    file(REMOVE_RECURSE "${_scratch}")
    set(${problems_var} "${_problems}" PARENT_SCOPE)
    return()
  endif()

  foreach(_target IN LISTS targets)
    get_filename_component(_target_dir "${_scratch}/tree/${_target}" DIRECTORY)
    file(MAKE_DIRECTORY "${_target_dir}")
    # A target the patch CREATES does not exist at the base. Absent here is the correct starting state, not an error.
    execute_process(
      COMMAND "${CMAKE_COMMAND}" -E env GIT_NO_REPLACE_OBJECTS=1
              "${GIT_EXECUTABLE}" show "${base_commit}:${_target}"
      WORKING_DIRECTORY "${submodule_dir}"
      OUTPUT_FILE "${_scratch}/tree/${_target}"
      RESULT_VARIABLE _show_rc
      ERROR_QUIET)
    if(NOT _show_rc EQUAL 0)
      file(REMOVE "${_scratch}/tree/${_target}")
    endif()
  endforeach()

  foreach(_patch IN LISTS patches)
    get_filename_component(_name "${_patch}" NAME)
    # The patch is applied from where it lives, byte for byte, so the reconstruction consumes exactly the input the
    # forward apply above consumed. Copying it through CMake would not be neutral: file(WRITE) re-expands LF to CRLF
    # on Windows, which would rewrite the LF encoding .gitattributes pins for these files and fail the apply.
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" apply --whitespace=nowarn -- "${_patch}"
      WORKING_DIRECTORY "${_scratch}/tree"
      RESULT_VARIABLE _rebuild_rc
      ERROR_VARIABLE _rebuild_error)
    if(NOT _rebuild_rc EQUAL 0)
      string(STRIP "${_rebuild_error}" _rebuild_error)
      list(APPEND _problems "patch '${_name}' does not apply to the pinned base blobs: ${_rebuild_error}")
      file(REMOVE_RECURSE "${_scratch}")
      set(${problems_var} "${_problems}" PARENT_SCOPE)
      return()
    endif()
  endforeach()

  foreach(_target IN LISTS targets)
    set(_expected "${_scratch}/tree/${_target}")
    set(_live "${submodule_dir}/${_target}")
    if(NOT EXISTS "${_expected}")
      # The patch removes this path. Absent on both sides is the patch's own outcome, not a difference.
      if(EXISTS "${_live}")
        list(APPEND _problems "'${_target}' should have been removed by the patch but is still present")
      endif()
      continue()
    endif()
    if(NOT EXISTS "${_live}")
      list(APPEND _problems "'${_target}' is absent from the submodule working tree")
      continue()
    endif()
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" diff --no-index --quiet --ignore-cr-at-eol -- "${_expected}" "${_live}"
      RESULT_VARIABLE _equal_rc
      OUTPUT_QUIET ERROR_QUIET)
    if(NOT _equal_rc EQUAL 0)
      # No semicolon in a problem string: CMake splits one list element into two on it, and the report below joins
      # elements with a newline, so a single drifted target would be reported as two unrelated problems.
      list(APPEND _problems
        "'${_target}' is not byte-equal to the reviewed patch output, so the configured backend carries an edit nobody reviewed")
    endif()
  endforeach()

  file(REMOVE_RECURSE "${_scratch}")
  set(${problems_var} "${_problems}" PARENT_SCOPE)
endfunction()

function(dmk_verify_backend_state submodule_dir patches base_commit)
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

  set(_set_agrees TRUE)
  foreach(_entry_path IN LISTS _changed)
    if(NOT _entry_path IN_LIST _expected)
      list(APPEND _problems "tracked edit outside the vendored patch: '${_entry_path}'")
      set(_set_agrees FALSE)
    endif()
  endforeach()
  foreach(_target IN LISTS _expected)
    if(NOT _target IN_LIST _changed)
      list(APPEND _problems "'${_target}' is unchanged although the vendored patch writes it")
      set(_set_agrees FALSE)
    endif()
  endforeach()

  # Only once the right files are the changed ones does comparing their bytes mean anything; a disagreeing set has
  # already been named above and a reconstruction over it would repeat that in less legible terms.
  if(_set_agrees AND _changed)
    dmk_reconstruct_backend_targets("${submodule_dir}" "${patches}" "${_expected}" "${base_commit}" _problems)
  endif()

  if(_problems)
    string(REPLACE ";" "\n  " _report "${_problems}")
    message(FATAL_ERROR
      "The configured SafetyHook backend is not exactly the reviewed patch output:\n  ${_report}\n"
      "Reset it and reconfigure:\n"
      "  git submodule update --init --force external/safetyhook")
  endif()
endfunction()

function(_dmk_apply_backend_patches_impl submodule_dir patch_dir base_commit)
  find_package(Git REQUIRED) # a fresh clone already needs git for `submodule update`

  set(_base_commit "${base_commit}")

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

  execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
    WORKING_DIRECTORY "${submodule_dir}"
    OUTPUT_VARIABLE _backend_head
    ERROR_VARIABLE _backend_head_error
    RESULT_VARIABLE _backend_head_rc
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _backend_head_rc EQUAL 0)
    string(STRIP "${_backend_head_error}" _backend_head_error)
    message(FATAL_ERROR "Could not resolve the SafetyHook backend HEAD: ${_backend_head_error}")
  endif()
  if(NOT "${_backend_head}" STREQUAL "${_base_commit}")
    message(FATAL_ERROR
      "The SafetyHook backend is at '${_backend_head}', not pinned base '${_base_commit}'.\n"
      "Reset it before configure:\n"
      "  git submodule update --init --force external/safetyhook")
  endif()

  if(DEFINED ENV{GIT_REPLACE_REF_BASE} AND NOT "$ENV{GIT_REPLACE_REF_BASE}" STREQUAL "")
    message(FATAL_ERROR
      "GIT_REPLACE_REF_BASE is set for the SafetyHook backend; the pinned commit's bytes cannot be trusted.\n"
      "Unset it before configure.")
  endif()

  # Replacement objects make a ref keep its pinned spelling while every object lookup resolves to another commit.
  # No configure may inherit that local rewrite: the reviewed base blobs are the objects named by the real pin.
  execute_process(
    COMMAND "${GIT_EXECUTABLE}" for-each-ref --format=%(refname) refs/replace
    WORKING_DIRECTORY "${submodule_dir}"
    OUTPUT_VARIABLE _replacement_refs
    ERROR_VARIABLE _replacement_refs_error
    RESULT_VARIABLE _replacement_refs_rc
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _replacement_refs_rc EQUAL 0)
    string(STRIP "${_replacement_refs_error}" _replacement_refs_error)
    message(FATAL_ERROR "Could not inspect SafetyHook replacement refs: ${_replacement_refs_error}")
  endif()
  if(NOT "${_replacement_refs}" STREQUAL "")
    message(FATAL_ERROR
      "The SafetyHook backend has replacement refs; the pinned commit's bytes cannot be trusted:\n"
      "  ${_replacement_refs}\n"
      "Delete the local refs/replace entries before configure.")
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
  dmk_verify_backend_state("${submodule_dir}" "${_patches}" "${_base_commit}")

  file(LOCK "${_dmk_patch_lock}" RELEASE)
endfunction()

function(dmk_apply_backend_patches submodule_dir patch_dir)
  if(NOT ARGC EQUAL 2)
    message(FATAL_ERROR "dmk_apply_backend_patches requires exactly the submodule and patch directories.")
  endif()
  _dmk_apply_backend_patches_impl("${submodule_dir}" "${patch_dir}" "${_DMK_BACKEND_BASE_COMMIT}")
endfunction()

# Script-mode entry point:
#   cmake -DDMK_SUBMODULE_DIR=<dir> -DDMK_PATCH_DIR=<dir> -P cmake/DMKBackendPatch.cmake
# runs the same apply-and-verify sequence a configure runs, so a route with no compiler (the blocking backend-patch
# quality job) can prove that THIS module turns the pristine pin into the reviewed backend. CMAKE_SCRIPT_MODE_FILE is
# set only under -P, so an ordinary include() from the root CMakeLists never reaches it.
if(CMAKE_SCRIPT_MODE_FILE AND "${CMAKE_SCRIPT_MODE_FILE}" STREQUAL "${CMAKE_CURRENT_LIST_FILE}")
  if(NOT DEFINED DMK_SUBMODULE_DIR OR NOT DEFINED DMK_PATCH_DIR)
    message(FATAL_ERROR "Script mode requires nonempty DMK_SUBMODULE_DIR and DMK_PATCH_DIR.")
  endif()
  if("${DMK_SUBMODULE_DIR}" STREQUAL "" OR "${DMK_PATCH_DIR}" STREQUAL "")
    message(FATAL_ERROR "Script mode requires nonempty DMK_SUBMODULE_DIR and DMK_PATCH_DIR.")
  endif()
  dmk_apply_backend_patches("${DMK_SUBMODULE_DIR}" "${DMK_PATCH_DIR}")
endif()
