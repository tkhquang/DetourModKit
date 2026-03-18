# Makefile wrapper for DetourModKit CMake build system
# All build configuration lives in CMakeLists.txt and CMakePresets.json

# Default presets (override with: make PRESET=msvc-release)
PRESET ?= mingw-release
TEST_PRESET ?= mingw-debug
JOBS ?= $(shell nproc 2>/dev/null || echo 4)

.PHONY: all configure build install test test_mingw test_msvc clean distclean help

# --- Build Targets ---
all: build

configure:
	cmake --preset $(PRESET)

build: configure
	cmake --build --preset $(PRESET) --parallel $(JOBS)

install: build
	cmake --install build/$(PRESET) --prefix build/install

# --- Test Targets ---
test:
	cmake --preset $(TEST_PRESET)
	cmake --build --preset $(TEST_PRESET) --parallel $(JOBS)
	ctest --preset $(TEST_PRESET)

test_mingw:
	$(MAKE) test TEST_PRESET=mingw-debug

test_msvc:
	$(MAKE) test TEST_PRESET=msvc-debug

# --- Housekeeping ---
clean:
	@echo "Cleaning preset build directories..."
	rm -rf build/mingw-debug build/mingw-release build/msvc-debug build/msvc-release

distclean:
	@echo "Full clean (entire build directory)..."
	rm -rf build

# --- Help ---
help:
	@echo "DetourModKit Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make              - Build library (PRESET=$(PRESET))"
	@echo "  make install      - Build and install to build/install/"
	@echo "  make test         - Build and run tests (TEST_PRESET=$(TEST_PRESET))"
	@echo "  make test_mingw   - Run tests with MinGW (Ninja)"
	@echo "  make test_msvc    - Run tests with MSVC (Ninja, requires VS dev shell)"
	@echo "  make clean        - Remove preset build directories"
	@echo "  make distclean    - Remove entire build/"
	@echo ""
	@echo "Override preset:  make PRESET=msvc-release"
	@echo "Override jobs:    make JOBS=8"
	@echo ""
	@echo "Available presets:"
	@echo "  mingw-debug       MinGW + Debug + Tests"
	@echo "  mingw-release     MinGW + Release (default)"
	@echo "  msvc-debug        MSVC + Debug + Tests"
	@echo "  msvc-release      MSVC + Release"
