cmake_minimum_required(VERSION 3.25)

project(DetourModKitPackageSmoke LANGUAGES CXX)

# Intentionally do NOT set CMAKE_CXX_STANDARD here. The installed DetourModKit target carries cxx_std_23 as a
# PUBLIC compile feature, so linking DetourModKit::DetourModKit must raise this consumer to C++23 on its own.
# Setting the standard locally would mask a regression where that requirement stopped being exported.

find_package(DetourModKit REQUIRED)

add_executable(dmk_package_smoke main.cpp)
target_link_libraries(dmk_package_smoke PRIVATE DetourModKit::DetourModKit)

enable_testing()
add_test(NAME dmk_package_smoke COMMAND dmk_package_smoke)
