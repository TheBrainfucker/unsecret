cmake_minimum_required(VERSION 3.20)
project(unsecret VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Ninja and Make build without optimisation unless told.
get_property(unsecret_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT unsecret_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(UNSECRET_SANITIZE "Build with sanitizers (ASan + UBSan; ASan only on MSVC)" OFF)
option(UNSECRET_BUILD_TESTS "Build unit tests" ON)
option(UNSECRET_BUILD_BENCH "Build the speed benchmark" ON)

if(UNSECRET_SANITIZE AND MINGW)
    message(FATAL_ERROR "MinGW GCC has no sanitizer support. Use MSVC, or run the sanitizer build on Linux.")
endif()

function(unsecret_configure_target target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    if(UNSECRET_SANITIZE)
        if(MSVC)
            # MSVC has ASan only. If Debug fails with it, use RelWithDebInfo.
            target_compile_options(${target} PRIVATE /fsanitize=address)
        else()
            # Without no-recover, UBSan only prints and the test still passes.
            target_compile_options(${target} PRIVATE
                -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all)
        endif()
    endif()
endfunction()

# Shared by the CLI and the tests.
add_library(unsecret_core
    src/regex_rule.cpp
    src/default_rules.cpp
    src/keyword_filter.cpp
    src/entropy_rule.cpp
    src/scanner.cpp
)
target_include_directories(unsecret_core PUBLIC include)
unsecret_configure_target(unsecret_core)

add_executable(unsecret src/main.cpp)
target_link_libraries(unsecret PRIVATE unsecret_core)
unsecret_configure_target(unsecret)

if(UNSECRET_BUILD_BENCH)
    add_executable(unsecret_bench bench/bench_scan.cpp)
    target_link_libraries(unsecret_bench PRIVATE unsecret_core)
    unsecret_configure_target(unsecret_bench)
endif()

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
        tests/test_default_rules.cpp
        tests/test_keyword_filter.cpp
        tests/test_scanner.cpp
    )
    target_link_libraries(unsecret_tests PRIVATE unsecret_core Catch2::Catch2WithMain)
    unsecret_configure_target(unsecret_tests)

    # One ctest entry per test case.
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(Catch)
    catch_discover_tests(unsecret_tests DISCOVERY_MODE PRE_TEST)
endif()
