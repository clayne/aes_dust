# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(aes_dust VERSION 1.0 LANGUAGES C)

# Set the output directories for libraries and executables
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_SUPPRESS_REGENERATION ON)

# Add the include directory for headers
include_directories(include)

# Specify the source files for the static library
set(SRC_FILES
    src/aes128_ecb.c
    src/aes128_cbc.c
    src/aes128_ctr.c
    src/aes128_gcm.c
    src/aes128_ofb.c
)

# Create the static library
add_library(aes128_static STATIC ${SRC_FILES})

# Add an executable for the test file
add_executable(test test.c)

# Link the static library to the test executable
target_link_libraries(test PRIVATE aes128_static)
