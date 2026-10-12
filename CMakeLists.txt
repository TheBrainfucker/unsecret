cmake_minimum_required(VERSION 3.20)
project(unsecret VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Single-config generators (Makefiles, Ninja) get no optimisation unless a build type is set.
get_property(unsecret_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT unsecret_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(UNSECRET_SANITIZE "Build with sanitizers (ASan + UBSan; ASan only on MSVC)" OFF)
option(UNSECRET_BUILD_TESTS "Build unit tests" ON)

if(UNSECRET_SANITIZE AND MINGW)
    message(FATAL_ERROR "MinGW GCC has no sanitizer support. Use MSVC, or run the sanitizer build on Linux.")
endif()

# Applies warnings and (optionally) sanitizers to a target,
# using the right flags for MSVC (Windows) or GCC/Clang (Linux, macOS, MinGW).
function(unsecret_configure_target target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(UNSECRET_SANITIZE)
        if(MSVC)
            # MSVC supports AddressSanitizer only (no UBSan).
            # Unverified: the Debug config adds /RTC1 and incremental linking, which ASan
            # does not support. If it errors, use --config RelWithDebInfo instead.
            target_compile_options(${target} PRIVATE /fsanitize=address)
        else()
            # -fno-sanitize-recover: UBSan otherwise only prints the error and the test still passes.
            target_compile_options(${target} PRIVATE
                -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
        endif()
    endif()
endfunction()

# Core logic as a library, so the CLI and the tests share the same code
add_library(unsecret_core
    src/regex_rule.cpp
    src/entropy_rule.cpp
    src/scanner.cpp
)
target_include_directories(unsecret_core PUBLIC include)
unsecret_configure_target(unsecret_core)

add_executable(unsecret src/main.cpp)
target_link_libraries(unsecret PRIVATE unsecret_core)
unsecret_configure_target(unsecret)

if(UNSECRET_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(Catch2)

    enable_testing()
    add_executable(unsecret_tests
        tests/test_rules.cpp
        tests/test_scanner.cpp
    )
    target_link_libraries(unsecret_tests PRIVATE unsecret_core Catch2::Catch2WithMain)
    unsecret_configure_target(unsecret_tests)

    # One CTest entry per test case, so ctest and the CI log name the failing test.
    # PRE_TEST lists the tests when ctest runs, not at build time.
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(Catch)
    catch_discover_tests(unsecret_tests DISCOVERY_MODE PRE_TEST)
endif()
