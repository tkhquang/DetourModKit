cmake_minimum_required(VERSION 3.28)

project(DetourModKitBuildTreeConsumer LANGUAGES CXX)

# Consume DetourModKit the way a vendoring mod does: add_subdirectory over the repository root with the default
# option set (tests off). main.cpp asserts at compile time that the backend and DMK's internal macro choices
# leave no trace on this consumer's command line, and windows_macro_probe.cpp proves the public headers compile
# after <windows.h> without NOMINMAX (with the min/max macros live on MSVC). Building this project on both
# toolchains is the permanent gate for backend confinement of the build-tree route.
#
# Intentionally no CMAKE_CXX_STANDARD: linking DetourModKit must raise this consumer to C++23 through the
# exported compile feature (main.cpp asserts the resulting language level).
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../.." detourmodkit)

add_executable(dmk_build_tree_consumer main.cpp windows_macro_probe.cpp)
target_link_libraries(dmk_build_tree_consumer PRIVATE DetourModKit)

# CI-runner workaround as in tests/package_smoke: embed the MinGW runtime so the proof binary is PATH-independent.
if(MINGW)
  target_link_options(dmk_build_tree_consumer PRIVATE -static -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_test(NAME dmk_build_tree_consumer COMMAND dmk_build_tree_consumer)
