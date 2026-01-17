add_executable(load_test
    load_test.cpp
)
add_executable(test
    test.cpp
)

target_link_libraries(load_test PRIVATE DLite)
target_link_libraries(test PRIVATE DLite)
