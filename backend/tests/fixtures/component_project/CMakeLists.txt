cmake_minimum_required(VERSION 3.20)
project(bigeye_component_fixture C)

option(BIGEYE_BUILD_FUZZERS "Build the release acceptance libFuzzer harnesses" ON)

add_library(bigeye_parser STATIC src/parser.c)
target_include_directories(bigeye_parser PUBLIC include)
target_compile_features(bigeye_parser PUBLIC c_std_11)
target_compile_options(bigeye_parser PRIVATE -Wall -Wextra -Wpedantic)

if(BIGEYE_BUILD_FUZZERS)
    target_compile_options(bigeye_parser PRIVATE
        -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)

    foreach(harness IN ITEMS correct incorrect)
        add_executable(bigeye_component_${harness} harnesses/${harness}.c)
        target_link_libraries(bigeye_component_${harness} PRIVATE bigeye_parser)
        target_compile_options(bigeye_component_${harness} PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
        target_link_options(bigeye_component_${harness} PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
