cmake_minimum_required(VERSION 3.20)
project(DLite)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(DLITE_ENABLE_CLANG_TIDY "Enable clang-tidy checks during build" OFF)
if (DLITE_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy clang-tidy.exe)
    if (CLANG_TIDY_EXE)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
    else()
        message(WARNING "clang-tidy enabled but not found on PATH")
    endif()
endif()

add_library(DLite STATIC
    src/loader.cpp
    src/pe_loader.cpp
    src/disasm.cpp
)

target_include_directories(DLite PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(capstone CONFIG REQUIRED)
target_link_libraries(DLite PUBLIC capstone::capstone)

if (WIN32)
    target_link_libraries(DLite PUBLIC comdlg32)
endif()

add_subdirectory(tests)
