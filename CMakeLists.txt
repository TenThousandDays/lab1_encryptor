cmake_minimum_required(VERSION 3.16)

project(FolderProtector VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(folder_protector
    src/main.cpp
    src/FileCryptor.cpp
    src/DirectoryProcessor.cpp
)

target_include_directories(folder_protector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(folder_protector PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
)
