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
get_target_property(_dmk_debug_location DetourModKit::DetourModKit IMPORTED_LOCATION_DEBUG)
get_target_property(_dmk_release_location DetourModKit::DetourModKit IMPORTED_LOCATION_RELEASE)
get_target_property(_dmk_relwithdebinfo_map DetourModKit::DetourModKit MAP_IMPORTED_CONFIG_RELWITHDEBINFO)
get_target_property(_dmk_minsizerel_map DetourModKit::DetourModKit MAP_IMPORTED_CONFIG_MINSIZEREL)
get_filename_component(_dmk_debug_name "${_dmk_debug_location}" NAME)
get_filename_component(_dmk_release_name "${_dmk_release_location}" NAME)
if(NOT _dmk_debug_name STREQUAL "libDetourModKitd${CMAKE_STATIC_LIBRARY_SUFFIX}")
  message(FATAL_ERROR "Debug imports '${_dmk_debug_location}', expected libDetourModKitd${CMAKE_STATIC_LIBRARY_SUFFIX}")
endif()
if(NOT _dmk_release_name STREQUAL "libDetourModKit${CMAKE_STATIC_LIBRARY_SUFFIX}")
  message(FATAL_ERROR
    "Release imports '${_dmk_release_location}', expected libDetourModKit${CMAKE_STATIC_LIBRARY_SUFFIX}")
endif()
if(NOT _dmk_relwithdebinfo_map STREQUAL "Release;RelWithDebInfo")
  message(FATAL_ERROR "RelWithDebInfo import map is '${_dmk_relwithdebinfo_map}', expected Release;RelWithDebInfo")
endif()
if(NOT _dmk_minsizerel_map STREQUAL "Release;MinSizeRel")
  message(FATAL_ERROR "MinSizeRel import map is '${_dmk_minsizerel_map}', expected Release;MinSizeRel")
endif()

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
target_link_libraries(dmk_dual_config_consumer PRIVATE DetourModKit::DetourModKit)

# CI-runner workaround as in tests/package_smoke: embed the MinGW runtime so the proof binary is PATH-independent.
if(MINGW)
  target_link_options(dmk_dual_config_consumer PRIVATE -static -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_test(NAME dmk_dual_config_consumer COMMAND dmk_dual_config_consumer)
set_tests_properties(dmk_dual_config_consumer PROPERTIES TIMEOUT 30)
