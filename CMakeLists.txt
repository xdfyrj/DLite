cmake_minimum_required(VERSION 3.20)
project(DLite)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CAPSTONE_DIR "C:/mingw64" CACHE PATH "Capstone install dir")

add_library(DLite STATIC
    src/loader.cpp
    src/pe_loader.cpp
    src/disasm.cpp
)

target_include_directories(DLite PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h
    PATHS "${CAPSTONE_DIR}"
    PATH_SUFFIXES include)
find_library(CAPSTONE_LIBRARY
    NAMES capstone libcapstone
    PATHS "${CAPSTONE_DIR}"
    PATH_SUFFIXES lib lib64)

if (NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
    message(FATAL_ERROR "Capstone not found under: ${CAPSTONE_DIR}")
endif()

target_include_directories(DLite PRIVATE "${CAPSTONE_INCLUDE_DIR}")
target_link_libraries(DLite PUBLIC "${CAPSTONE_LIBRARY}")

if (WIN32)
    target_link_libraries(DLite PUBLIC comdlg32)
endif()

add_subdirectory(test)
