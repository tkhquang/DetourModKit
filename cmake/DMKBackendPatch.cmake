# The external/safetyhook submodule is pinned to a commit the configured upstream remote serves
# (cursey/safetyhook main, f44cc07), so `git submodule update --init` resolves it on a fresh clone.
# DMK's two backend fixes -- trap-transaction status reporting and post-static-destruction teardown --
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
# (both fixes, regenerable via `git -C external/safetyhook diff <base> <reviewed>`).
function(dmk_apply_backend_patches submodule_dir patch_dir)
  find_package(Git REQUIRED) # a fresh clone already needs git for `submodule update`

  file(GLOB _patches LIST_DIRECTORIES false "${patch_dir}/*.patch")
  list(SORT _patches) # deterministic order; each patch is an independent net delta (see above)

  if(NOT _patches)
    message(FATAL_ERROR
      "No backend patches found in '${patch_dir}'. The vendored SafetyHook fixes would be dropped and "
      "the backend would build without the trap-transaction and static-teardown corrections. Restore "
      "cmake/safetyhook_patches/ from version control.")
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
endfunction()
