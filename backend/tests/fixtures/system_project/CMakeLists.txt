cmake_minimum_required(VERSION 3.20)
project(bigeye_system_fixture C)

option(BIGEYE_DEFAULT_FRAMED "Use the framed input configuration unless --mode overrides it" OFF)

add_executable(bigeye_system_fixture src/main.c)
target_compile_features(bigeye_system_fixture PRIVATE c_std_11)
target_compile_options(bigeye_system_fixture PRIVATE -Wall -Wextra -Wpedantic)
if(BIGEYE_DEFAULT_FRAMED)
    target_compile_definitions(bigeye_system_fixture PRIVATE BIGEYE_DEFAULT_FRAMED=1)
else()
    target_compile_definitions(bigeye_system_fixture PRIVATE BIGEYE_DEFAULT_FRAMED=0)
endif()
