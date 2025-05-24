# Makefile for building DetourModKit static library

# --- Toolchain ---
CXX := g++
AR := ar

# --- Project Directories ---
KIT_NAME := DetourModKit
SRC_DIR := src
# Where your project's public headers are BEFORE installation
# e.g., if you have "DetourModKit_Root/include/DetourModKit/logger.hpp"
PUBLIC_HEADER_SOURCE_ROOT_DIR := include
PUBLIC_HEADER_SOURCE_SUBDIR := $(PUBLIC_HEADER_SOURCE_ROOT_DIR)/$(KIT_NAME)

EXTERNAL_DIR := external
BUILD_DIR := build

# --- Output Directories for Installation ---
INSTALL_DIR := $(BUILD_DIR)/install
INSTALL_LIB_DIR := $(INSTALL_DIR)/lib
# For DetourModKit's own headers when installed
INSTALL_KIT_INCLUDE_DIR := $(INSTALL_DIR)/include/$(KIT_NAME)
# For general dependency headers (like SimpleIni.h, safetyhook.hpp at the top level of include)
INSTALL_GENERAL_INCLUDE_DIR := $(INSTALL_DIR)/include
# For SafetyHook's namespaced headers (e.g. include/safetyhook/common.hpp)
INSTALL_SAFETYHOOK_SUB_INCLUDE_DIR := $(INSTALL_GENERAL_INCLUDE_DIR)/safetyhook


# For object files
OBJ_DIR := $(BUILD_DIR)/obj

# --- Dependency Source and Include Directories ---
SAFETYHOOK_SUBMODULE_DIR := $(EXTERNAL_DIR)/safetyhook
SAFETYHOOK_BUILD_DIR := $(SAFETYHOOK_SUBMODULE_DIR)/build
# Path to SafetyHook's "include" directory as a source for copying headers
# This is based on your sanity check. Adjust if SafetyHook structures its includes differently.
SAFETYHOOK_HEADERS_SOURCE_DIR := $(SAFETYHOOK_SUBMODULE_DIR)/include
# Also consider the main safetyhook.hpp if it's at the root of the submodule
SAFETYHOOK_MAIN_HEADER_SOURCE := $(SAFETYHOOK_SUBMODULE_DIR)/safetyhook.hpp


SIMPLEINI_SUBMODULE_DIR := $(EXTERNAL_DIR)/simpleini

# --- Statically Built Libraries from SafetyHook ---
# These paths assume SafetyHook is built by its own CMake into its own `build` subdir.
BUILT_SAFETYHOOK_LIB := $(SAFETYHOOK_BUILD_DIR)/libsafetyhook.a
# For Zydis/Zycore, paths depend on how SafetyHook's CMake configures them.
# These are common defaults if SafetyHook uses CMake's ExternalProject or FetchContent.
BUILT_ZYDIS_LIB := $(SAFETYHOOK_BUILD_DIR)/_deps/zydis-build/libZydis.a
BUILT_ZYCORE_LIB := $(SAFETYHOOK_BUILD_DIR)/_deps/zydis-build/zycore/libZycore.a

# --- Dependency List for SafetyHook itself ---
SAFETYHOOK_DEPS_LIBS := $(BUILT_SAFETYHOOK_LIB) $(BUILT_ZYDIS_LIB) $(BUILT_ZYCORE_LIB)

# --- DetourModKit Target ---
TARGET_LIB := $(INSTALL_LIB_DIR)/lib$(KIT_NAME).a

# --- Sanity Checks ---
ifeq ($(wildcard $(SAFETYHOOK_SUBMODULE_DIR)/CMakeLists.txt),)
$(error SafetyHook directory or its CMakeLists.txt not found at $(SAFETYHOOK_SUBMODULE_DIR). Please ensure the submodule is initialized and populated.)
endif
ifeq ($(wildcard $(SAFETYHOOK_HEADERS_SOURCE_DIR)/safetyhook/inline_hook.hpp),)
$(error SafetyHook public headers not found. Expected e.g.: $(SAFETYHOOK_HEADERS_SOURCE_DIR)/safetyhook/inline_hook.hpp. Ensure SafetyHook submodule is correct.)
endif
ifeq ($(wildcard $(SIMPLEINI_SUBMODULE_DIR)/SimpleIni.h),)
$(error SimpleIni.h not found at $(SIMPLEINI_SUBMODULE_DIR). Please ensure the submodule is initialized and populated.)
endif

# --- Common Compiler Flags for DetourModKit ---
# For compiling DetourModKit's own sources:
INTERNAL_INCLUDE_PATHS := \
    -I$(PUBLIC_HEADER_SOURCE_ROOT_DIR) \
    -I$(SAFETYHOOK_HEADERS_SOURCE_DIR) \
    -I$(SAFETYHOOK_SUBMODULE_DIR) \
    -I$(SIMPLEINI_SUBMODULE_DIR)

COMMON_DEFINES := \
    -DWINVER=0x0A00 \
    -D_WIN32_WINNT=0x0A00 \
    -DSAFETYHOOK_NO_DLL \
    -DZYDIS_STATIC_BUILD \
    -DZYCORE_STATIC_BUILD

COMMON_CXXFLAGS := -m64 -Wall -Wextra $(INTERNAL_INCLUDE_PATHS) -fexceptions -fPIC $(COMMON_DEFINES) $(SUPPRESS_WARNINGS)
CXX_STANDARD_FLAG := -std=c++23
OPTIMIZATION_FLAGS := -O2
RELEASE_CXXFLAGS := $(COMMON_CXXFLAGS) $(CXX_STANDARD_FLAG) $(OPTIMIZATION_FLAGS)

# --- Source Files ---
KIT_CPP_SRCS := $(wildcard $(SRC_DIR)/*.cpp)
KIT_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(KIT_CPP_SRCS))

# --- Main Target Rule ---
.PHONY: all
all: $(TARGET_LIB)

# --- Rule to Build SafetyHook & Dependencies ---
$(BUILT_SAFETYHOOK_LIB): $(SAFETYHOOK_SUBMODULE_DIR)/CMakeLists.txt
	@echo "---- Building SafetyHook & its dependencies (Zydis, Zycore) via CMake ----"
	@cd $(SAFETYHOOK_SUBMODULE_DIR) && \
	  cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DSAFETYHOOK_BUILD_TESTS=OFF -DSAFETYHOOK_BUILD_EXAMPLES=OFF && \
	  cmake --build build --config Release --parallel $(shell nproc || echo 2)
	@if [ ! -f "$(BUILT_SAFETYHOOK_LIB)" ]; then \
		echo "ERROR: SafetyHook library not found: $(BUILT_SAFETYHOOK_LIB)"; exit 1; \
	fi
	@if [ ! -f "$(BUILT_ZYDIS_LIB)" ]; then \
		echo "ERROR: Zydis library not found: $(BUILT_ZYDIS_LIB)"; exit 1; \
	fi
	@if [ ! -f "$(BUILT_ZYCORE_LIB)" ]; then \
		echo "ERROR: Zycore library not found: $(BUILT_ZYCORE_LIB)"; exit 1; \
	fi
	@echo "---- SafetyHook & dependencies build attempt complete. ----"

# --- Target Library Creation ---
$(TARGET_LIB): $(SAFETYHOOK_DEPS_LIBS) $(KIT_OBJS)
	@echo "Creating static library $(TARGET_LIB)..."
	@mkdir -p $(INSTALL_LIB_DIR)
	$(AR) rcs $@ $(KIT_OBJS)
	@echo "Static library $(KIT_NAME) built: $@"

# --- Object File Compilation ---
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@echo "Compiling C++ (DetourModKit) $<"
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(RELEASE_CXXFLAGS) -c $< -o $@

# --- Install Target ---
.PHONY: install
install: $(TARGET_LIB)
	@echo "Installing $(KIT_NAME) library and headers..."
	@mkdir -p $(INSTALL_KIT_INCLUDE_DIR)
	@mkdir -p $(INSTALL_SAFETYHOOK_SUB_INCLUDE_DIR) # For build/install/include/safetyhook/
	@mkdir -p $(INSTALL_GENERAL_INCLUDE_DIR)        # For build/install/include/
	@mkdir -p $(INSTALL_LIB_DIR)

	# 1. Copy DetourModKit's public headers
	@echo "Copying DetourModKit headers from $(PUBLIC_HEADER_SOURCE_SUBDIR) ..."
	cp -v $(PUBLIC_HEADER_SOURCE_SUBDIR)/*.hpp $(INSTALL_KIT_INCLUDE_DIR)/

	# 2. Copy SimpleIni.h
	@echo "Copying SimpleIni header from $(SIMPLEINI_SUBMODULE_DIR) ..."
	cp -v $(SIMPLEINI_SUBMODULE_DIR)/SimpleIni.h $(INSTALL_GENERAL_INCLUDE_DIR)/

	# 3. Copy SafetyHook main header (e.g., external/safetyhook/safetyhook.hpp)
	# This header itself likely does #include <safetyhook/common.hpp> etc.
	@echo "Copying SafetyHook main header from $(SAFETYHOOK_SUBMODULE_DIR) ..."
	@if [ -f "$(SAFETYHOOK_MAIN_HEADER_SOURCE)" ]; then \
		cp -v $(SAFETYHOOK_MAIN_HEADER_SOURCE) $(INSTALL_GENERAL_INCLUDE_DIR)/ ; \
	else \
		echo "Warning: Main safetyhook.hpp not found at $(SAFETYHOOK_SUBMODULE_DIR)/safetyhook.hpp, skipping."; \
	fi

	# 4. Copy SafetyHook's namespaced headers (e.g., external/safetyhook/safetyhook/*.hpp)
	# These are the headers that safetyhook.hpp would include.
	# The target directory $(INSTALL_SAFETYHOOK_SUB_INCLUDE_DIR) is build/install/include/safetyhook/
	@echo "Copying SafetyHook namespaced headers from $(SAFETYHOOK_SUBMODULE_DIR)/safetyhook ..."
	@if [ -d "$(SAFETYHOOK_SUBMODULE_DIR)/safetyhook" ]; then \
		cp -vr $(SAFETYHOOK_SUBMODULE_DIR)/safetyhook/* $(INSTALL_SAFETYHOOK_SUB_INCLUDE_DIR)/ ; \
	else \
		echo "Warning: SafetyHook subdirectory headers not found at $(SAFETYHOOK_SUBMODULE_DIR)/safetyhook, skipping."; \
	fi

	# $(TARGET_LIB) is already built into $(INSTALL_LIB_DIR) by its own rule.

	# 5. Copy dependency static libraries
	@echo "Copying dependency libraries (SafetyHook, Zydis, Zycore) to install directory..."
	cp -v $(BUILT_SAFETYHOOK_LIB) $(INSTALL_LIB_DIR)/
	cp -v $(BUILT_ZYDIS_LIB) $(INSTALL_LIB_DIR)/
	cp -v $(BUILT_ZYCORE_LIB) $(INSTALL_LIB_DIR)/

	@echo ""
	@echo "$(KIT_NAME) installation complete in $(INSTALL_DIR)"
	@echo "------------------------------------------------------------"
	@echo "To use DetourModKit in your project (Makefile based):"
	@echo "  Add to CXXFLAGS/INCLUDE_PATHS: -I$(INSTALL_DIR)/include"
	@echo "  Add to LDFLAGS:                -L$(INSTALL_DIR)/lib"
	@echo "  Link with LIBS:                -l$(KIT_NAME) -lsafetyhook -lZydis -lZycore"
	@echo "                                 (plus any system libraries your mod needs)"
	@echo "Example includes in your code:"
	@echo "  #include <DetourModKit/logger.hpp>"
	@echo "  #include <safetyhook.hpp>"
	@echo "  #include <SimpleIni.h>"
	@echo "------------------------------------------------------------"


# --- Housekeeping Targets ---
.PHONY: prepare_dirs
prepare_dirs:
	@echo "Creating build directories..."
	@mkdir -p $(BUILD_DIR) $(OBJ_DIR) $(INSTALL_DIR) $(INSTALL_LIB_DIR) $(INSTALL_KIT_INCLUDE_DIR) $(INSTALL_GENERAL_INCLUDE_DIR) $(INSTALL_SAFETYHOOK_SUB_INCLUDE_DIR)

.PHONY: clean
clean:
	@echo "Cleaning $(KIT_NAME) build files..."
	rm -rf $(OBJ_DIR) $(INSTALL_DIR)

.PHONY: clean_safetyhook
clean_safetyhook:
	@echo "Cleaning SafetyHook build directory: $(SAFETYHOOK_BUILD_DIR)..."
	@cd $(SAFETYHOOK_SUBMODULE_DIR) && rm -rf build

.PHONY: distclean
distclean: clean clean_safetyhook
	@echo "Performing full clean (DetourModKit output and SafetyHook build outputs)..."
	rm -rf $(BUILD_DIR)

# --- Help Target ---
.PHONY: help
help:
	@echo "DetourModKit Makefile"
	@echo "Available targets:"
	@echo "  make all (or make)    - Build the DetourModKit static library"
	@echo "  make install          - Build and install the library, all headers, and dependency libs to $(INSTALL_DIR)/"
	@echo "  make clean            - Remove DetourModKit object files and the install directory."
	@echo "  make clean_safetyhook - Remove SafetyHook's build directory."
	@echo "  make distclean        - Perform 'clean' and 'clean_safetyhook'."
	@echo "  make help             - Display this help message."
