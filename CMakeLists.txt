cmake_minimum_required(VERSION 3.20)
project(DLite)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(DLite STATIC
    src/loader.cpp
)

target_include_directories(DLite PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (WIN32)
    target_link_libraries(DLite PUBLIC comdlg32)
endif()

add_subdirectory(test)
