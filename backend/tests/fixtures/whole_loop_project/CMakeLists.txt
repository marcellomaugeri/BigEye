cmake_minimum_required(VERSION 3.20)
project(decoder C)

add_library(decoder STATIC src/decoder.c)
target_include_directories(decoder PUBLIC include)
target_compile_features(decoder PUBLIC c_std_11)
target_compile_options(decoder PRIVATE -Wall -Wextra -Wpedantic)

add_executable(decoder_cli src/decoder_cli.c)
target_link_libraries(decoder_cli PRIVATE decoder)
target_compile_features(decoder_cli PRIVATE c_std_11)
target_compile_options(decoder_cli PRIVATE -Wall -Wextra -Wpedantic)
