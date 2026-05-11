cmake_minimum_required(VERSION 3.16)

project(FolderProtector
    VERSION 1.0.0
    DESCRIPTION "Lab 1 - Folder encryptor"
    LANGUAGES CXX)

option(ENABLE_SANITIZERS "Enable asan and ubsan support" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_executable(folder_protector
    src/main.cpp
    src/DirectoryProcessor.cpp
    src/FileCryptor.cpp)

target_include_directories(folder_protector PRIVATE include)
target_link_libraries(folder_protector PRIVATE OpenSSL::Crypto)

if (MSVC)
    target_compile_options(folder_protector PRIVATE /W4 /permissive-)
else()
    target_compile_options(folder_protector PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Woverloaded-virtual
        -Wnull-dereference
        -Wformat=2)
endif()

if (ENABLE_SANITIZERS AND NOT MSVC)
    target_compile_options(folder_protector PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(folder_protector PRIVATE -fsanitize=address,undefined)
endif()
