cmake_minimum_required(VERSION 3.19)
project(maml
    VERSION 0.1.0
    DESCRIPTION "Byte-pattern matching for binaries, with a seed-then-refine scanner"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Static analysis, opt-in: -DMAML_CLANG_TIDY=ON. Off by default because it
# roughly doubles build time, and because a check that runs on every build
# without anyone having chosen it is a check people learn to route around.
option(MAML_CLANG_TIDY "Run clang-tidy as part of the build" OFF)
if(MAML_CLANG_TIDY)
    find_program(MAML_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    # The vendored Catch2 header alone accounts for ~2,800 findings, so the
    # .clang-tidy HeaderFilterRegex is what keeps this readable; see that file.
    set(CMAKE_CXX_CLANG_TIDY "${MAML_CLANG_TIDY_EXE}")
    message(STATUS "clang-tidy: ${MAML_CLANG_TIDY_EXE}")
endif()

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MAML_MAIN_PROJECT ON)
else()
    set(MAML_MAIN_PROJECT OFF)
endif()

option(MAML_BUILD_TESTS "Build tests" ${MAML_MAIN_PROJECT})
option(MAML_BUILD_TOOLS "Build the mamlscan CLI" ${MAML_MAIN_PROJECT})

# ── the library ────────────────────────────────────────────────────────
# Header-only. Consumers include <maml/v1.hpp> and
# <maml/mamlscan.hpp>, or <maml.hpp> for both.

add_library(maml INTERFACE)
add_library(maml::maml ALIAS maml)

target_include_directories(maml INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(maml INTERFACE cxx_std_20)

# ── mamlscan: the CLI ────────────────────────────────────────────────────
# Scans an image for a pattern, or runs a whole jobfile against several
# images with one load each. This is what drives the dual-build audit.

if(MAML_BUILD_TOOLS)
    add_executable(mamlscan tools/mamlscan.cpp)
    target_link_libraries(mamlscan PRIVATE maml)

    # The locator pipeline: compose the substrate generate.hpp derives into a
    # search for an address ("str ... -> xref -> func"). Same manifest the
    # durability harness reads, so the two compose.
    add_executable(mamlpipe tools/mamlpipe.cpp)
    target_link_libraries(mamlpipe PRIVATE maml)

    # Throughput of the literal scan. Built with the tools so CI can report a
    # per-platform number: the SSE2 path had never been measured on real x86.
    add_executable(mamlbench tools/mamlbench.cpp)
    target_link_libraries(mamlbench PRIVATE maml)

    # The durability harness. Compiled, never run here: it needs several real
    # builds of the same binary, which are large and not redistributable.
    # Compile the harnesses to catch API drift without requiring private fixtures.
    add_executable(maml.durability.measure tools/durability/measure.cpp)
    target_link_libraries(maml.durability.measure PRIVATE maml)
    add_executable(maml.durability.resolve tools/durability/resolve.cpp)
    target_link_libraries(maml.durability.resolve PRIVATE maml)
    if(NOT MSVC)
        target_compile_options(mamlscan PRIVATE -O2)
        target_compile_options(mamlpipe PRIVATE -O2)
    endif()
endif()

# ── tests ──────────────────────────────────────────────────────────────
# Catch2 v2 is vendored rather than fetched: these tests must build with no
# network, and a single header is a cheap way to guarantee that.

if(MAML_BUILD_TESTS)
    enable_testing()

    add_library(catch2_vendored INTERFACE)
    target_include_directories(catch2_vendored INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/catch2)

    add_executable(maml_tests
        tests/main.cpp
        tests/test_generate.cpp
        tests/test_simd_backend.cpp
        tests/test_v1.cpp
    )
    target_link_libraries(maml_tests PRIVATE maml catch2_vendored)
    if(NOT MSVC)
        target_compile_options(maml_tests PRIVATE -O1)
    endif()

    add_test(NAME maml_tests COMMAND maml_tests)
endif()

# ── install ────────────────────────────────────────────────────────────

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS maml EXPORT maml-targets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT maml-targets
    FILE maml-targets.cmake
    NAMESPACE maml::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/maml)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/maml-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/maml-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/maml)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/maml-config-version.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/maml-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/maml-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/maml)
