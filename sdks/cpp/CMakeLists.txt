cmake_minimum_required(VERSION 3.15)
project(vouch_core_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Import the prebuilt core library and its C header (cbindgen-generated).
add_library(vouch_core SHARED IMPORTED GLOBAL)
set_target_properties(vouch_core PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/lib/libvouch_core_uniffi.so"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_executable(example examples/example.c)
target_link_libraries(example PRIVATE vouch_core)

# Find the shared library next to the example at build/run time.
set_target_properties(example PROPERTIES
    BUILD_RPATH "${CMAKE_CURRENT_SOURCE_DIR}/lib")
