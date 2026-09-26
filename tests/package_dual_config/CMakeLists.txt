cmake_minimum_required(VERSION 3.28)

project(DetourModKitDualConfigConsumer LANGUAGES CXX)

# Intentionally no CMAKE_CXX_STANDARD: linking DetourModKit raises this consumer to C++23 through the exported
# cxx_std_23 compile feature. main.cpp includes <DetourModKit.hpp>, whose C++23 std types fail to compile unless that
# raise took effect, so the build itself is the enforcement (installed consumers do not assert __cplusplus directly,
# matching tests/package_smoke).
find_package(DetourModKit REQUIRED)

foreach(_dmk_package_internal IN ITEMS
    _dmk_consumer_family _dmk_consumer_stl _dmk_producer_family
    _dmk_consumer_major _dmk_producer_major _dmk_consumer_arch _dmk_producer_arch
    _dmk_abi_errors _dmk_abi_warnings _dmk_abi_error_text _dmk_abi_rejected _dmk_error _dmk_w
    _dmk_dep_release_names _dmk_dep_debug_names _dmk_dep_libdir _dmk_dep_libs _dmk_dep_count _dmk_dep_last
    _dmk_dep_rel _dmk_dep_dbg _dmk_dep_link _dmk_i)
  if(DEFINED ${_dmk_package_internal})
    message(FATAL_ERROR "DetourModKitConfig.cmake leaked internal variable ${_dmk_package_internal}")
  endif()
endforeach()

# Prove selection from target metadata as well as from a successful link. MinGW can link a Release archive into a
# Debug consumer without an MSVC-style mismatch diagnostic, so runtime success alone cannot distinguish the files.
# Every compiled target in the prefix selects its Debug and Release archives, and maps both release-family configs.
function(dmk_expect_config_selection target archive)
  get_target_property(debug_location ${target} IMPORTED_LOCATION_DEBUG)
  get_target_property(release_location ${target} IMPORTED_LOCATION_RELEASE)
  get_filename_component(debug_name "${debug_location}" NAME)
  get_filename_component(release_name "${release_location}" NAME)
  if(NOT debug_name STREQUAL "lib${archive}d${CMAKE_STATIC_LIBRARY_SUFFIX}")
    message(FATAL_ERROR
      "${target} Debug imports '${debug_location}', expected lib${archive}d${CMAKE_STATIC_LIBRARY_SUFFIX}")
  endif()
  if(NOT release_name STREQUAL "lib${archive}${CMAKE_STATIC_LIBRARY_SUFFIX}")
    message(FATAL_ERROR
      "${target} Release imports '${release_location}', expected lib${archive}${CMAKE_STATIC_LIBRARY_SUFFIX}")
  endif()
  foreach(config IN ITEMS RelWithDebInfo MinSizeRel)
    string(TOUPPER "${config}" config_upper)
    get_target_property(config_map ${target} MAP_IMPORTED_CONFIG_${config_upper})
    if(NOT config_map STREQUAL "Release;${config}")
      message(FATAL_ERROR "${target} ${config} import map is '${config_map}', expected Release;${config}")
    endif()
  endforeach()
endfunction()

dmk_expect_config_selection(DetourModKit::DetourModKit DetourModKit)
dmk_expect_config_selection(DetourModKit::WheelHost DetourModKitWheelHost)

get_target_property(_dmk_release_location DetourModKit::DetourModKit IMPORTED_LOCATION_RELEASE)
get_filename_component(_dmk_libdir "${_dmk_release_location}" DIRECTORY)
get_target_property(_dmk_dep_links DetourModKit::deps INTERFACE_LINK_LIBRARIES)
foreach(_dmk_dependency IN ITEMS safetyhook Zydis Zycore)
  set(_dmk_debug_dep "${_dmk_libdir}/${CMAKE_STATIC_LIBRARY_PREFIX}${_dmk_dependency}d${CMAKE_STATIC_LIBRARY_SUFFIX}")
  set(_dmk_release_dep "${_dmk_libdir}/${CMAKE_STATIC_LIBRARY_PREFIX}${_dmk_dependency}${CMAKE_STATIC_LIBRARY_SUFFIX}")
  set(_dmk_expected_link
    "$<$<CONFIG:Debug>:${_dmk_debug_dep}>$<$<NOT:$<CONFIG:Debug>>:${_dmk_release_dep}>")
  list(FIND _dmk_dep_links "${_dmk_expected_link}" _dmk_link_index)
  if(_dmk_link_index EQUAL -1)
    message(FATAL_ERROR
      "DetourModKit::deps does not select the expected Debug/Release archives for ${_dmk_dependency}: "
      "${_dmk_dep_links}")
  endif()
endforeach()

add_executable(dmk_dual_config_consumer main.cpp)
target_link_libraries(dmk_dual_config_consumer PRIVATE DetourModKit::DetourModKit DetourModKit::WheelHost)

# CI-runner workaround as in tests/package_smoke: embed the MinGW runtime so the proof binary is PATH-independent.
if(MINGW)
  target_link_options(dmk_dual_config_consumer PRIVATE -static -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_test(NAME dmk_dual_config_consumer COMMAND dmk_dual_config_consumer)
set_tests_properties(dmk_dual_config_consumer PROPERTIES TIMEOUT 30)
