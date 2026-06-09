cmake_minimum_required(VERSION 3.25)

project(DetourModKitPackageSmoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(DetourModKit REQUIRED)

add_executable(dmk_package_smoke main.cpp)
target_link_libraries(dmk_package_smoke PRIVATE DetourModKit::DetourModKit)

enable_testing()
add_test(NAME dmk_package_smoke COMMAND dmk_package_smoke)
