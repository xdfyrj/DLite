cmake_minimum_required(VERSION 3.20)
project(DLite)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(DLite STATIC
    src/loader.cpp
    src/pe_loader.cpp
    src/disasm.cpp
)
