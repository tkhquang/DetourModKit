# Makefile wrapper for DetourModKit CMake build system
# All build configuration lives in CMakeLists.txt and CMakePresets.json

# Default presets (override with: make PRESET=msvc-release)
PRESET ?= mingw-release
TEST_PRESET ?= mingw-debug
JOBS ?= $(shell nproc 2>/dev/null || echo 4)

.PHONY: all configure build install test test_mingw test_msvc test_asan clean distclean help

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

# AddressSanitizer build + tests. MSVC only: GCC and Clang on mingw-w64 ship no
# ASan/UBSan runtime for the Windows target, so the sanitizer build links only
# under MSVC (ASan only). Run from a Visual Studio Developer Command Prompt.
test_asan:
	$(MAKE) test TEST_PRESET=msvc-debug-asan

# --- Housekeeping ---
clean:
	@echo "Cleaning preset build directories..."
	rm -rf build/mingw-debug build/mingw-release build/msvc-debug build/msvc-release build/mingw-debug-coverage build/msvc-debug-asan

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
	@echo "  make test_asan    - Run tests under MSVC AddressSanitizer (VS dev shell)"
	@echo "  make clean        - Remove preset build directories"
	@echo "  make distclean    - Remove entire build/"
	@echo ""
	@echo "Override preset:  make PRESET=msvc-release"
	@echo "Override jobs:    make JOBS=8"
	@echo ""
	@echo "Available presets:"
	@echo "  mingw-debug           MinGW + Debug + Tests"
	@echo "  mingw-debug-coverage  MinGW + Debug + gcov coverage"
	@echo "  mingw-release         MinGW + Release (default)"
	@echo "  msvc-debug            MSVC + Debug + Tests"
	@echo "  msvc-debug-asan       MSVC + Debug + AddressSanitizer"
	@echo "  msvc-release          MSVC + Release"
