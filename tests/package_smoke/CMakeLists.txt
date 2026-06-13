cmake_minimum_required(VERSION 3.25)

project(DetourModKitPackageSmoke LANGUAGES CXX)

# Intentionally do NOT set CMAKE_CXX_STANDARD here. The installed DetourModKit target carries cxx_std_23 as a
# PUBLIC compile feature, so linking DetourModKit::DetourModKit must raise this consumer to C++23 on its own.
# Setting the standard locally would mask a regression where that requirement stopped being exported.

find_package(DetourModKit REQUIRED)

add_executable(dmk_package_smoke main.cpp)
target_link_libraries(dmk_package_smoke PRIVATE DetourModKit::DetourModKit)

# Statically link the GCC runtime on MinGW. This is a CI-runner workaround, not a consumer recommendation: a
# Windows runner can resolve a mismatched libstdc++ / libgcc / libwinpthread on PATH than the toolchain that built
# the exe, which makes the smoke binary hang at startup/teardown. Embedding the runtime makes it self-contained so
# the installed-package check is PATH-independent, without changing what is verified here (find_package wiring and
# the exported C++23 requirement).
if(MINGW)
  target_link_options(dmk_package_smoke PRIVATE -static -static-libgcc -static-libstdc++)
endif()

enable_testing()
add_test(NAME dmk_package_smoke COMMAND dmk_package_smoke)
