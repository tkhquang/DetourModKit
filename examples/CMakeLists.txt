# Debug presets compile these reference examples to detect public API drift. No example has an install or test rule.

# Apply the first-party warning and compile-hardening flags to both examples.
add_compile_options(${DMK_WARNING_COMPILE_OPTIONS} ${DMK_HARDENING_COMPILE_OPTIONS})

# One name drives the deployed pair (ModName.asi, ModName.logic.dll) and every derived file name in both TUs.
set(DMK_EXAMPLE_MOD_NAME "StagedExample")

# The logic DLL links one archive instance, exactly like a release mod build. dmk_coverage supplies the gcov
# runtime when the archive is instrumented, and stays inert otherwise.
add_library(dmk_example_staged_logic SHARED staged_reload/mod_logic.cpp)
set_target_properties(dmk_example_staged_logic PROPERTIES PREFIX "" OUTPUT_NAME "${DMK_EXAMPLE_MOD_NAME}.logic")
target_compile_definitions(dmk_example_staged_logic PRIVATE DMK_EXAMPLE_MOD_NAME="${DMK_EXAMPLE_MOD_NAME}")
target_link_libraries(dmk_example_staged_logic PRIVATE DetourModKit dmk_coverage)

# The loader links only the resident wheel host. It never links the full DetourModKit archive.
add_library(dmk_example_staged_loader SHARED staged_reload/mod_loader.cpp)
set_target_properties(dmk_example_staged_loader PROPERTIES PREFIX "" OUTPUT_NAME "${DMK_EXAMPLE_MOD_NAME}")
target_compile_definitions(dmk_example_staged_loader PRIVATE DMK_EXAMPLE_MOD_NAME="${DMK_EXAMPLE_MOD_NAME}")
target_link_libraries(dmk_example_staged_loader PRIVATE DetourModKit::WheelHost dmk_coverage)
target_link_options(dmk_example_staged_loader PRIVATE ${DMK_HARDENING_LINK_OPTIONS})

# Embed the MinGW runtimes, winpthread included, so the pair deploys without toolchain DLLs.
if(MINGW)
  target_link_options(dmk_example_staged_logic PRIVATE -static -static-libgcc -static-libstdc++)
  target_link_options(dmk_example_staged_loader PRIVATE -static -static-libgcc -static-libstdc++)
endif()

# Require the resident target and reject any full-archive edge.
get_target_property(_dmk_example_loader_links dmk_example_staged_loader LINK_LIBRARIES)
if(NOT _dmk_example_loader_links MATCHES "DetourModKit::WheelHost")
  message(FATAL_ERROR "dmk_example_staged_loader must link DetourModKit::WheelHost.")
endif()
if(_dmk_example_loader_links MATCHES "DetourModKit::DetourModKit" OR
   _dmk_example_loader_links MATCHES "(^|;)DetourModKit(;|$)")
  message(FATAL_ERROR "dmk_example_staged_loader must not link the full DetourModKit archive.")
endif()
