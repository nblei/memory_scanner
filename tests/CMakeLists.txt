# tests/CMakeLists.txt
find_package(GTest REQUIRED)

add_executable(pointer_scanner_test
    pointer_scanner_test.cc
)

target_link_libraries(pointer_scanner_test
    PRIVATE
        pointer_scanner
        GTest::GTest
        GTest::Main
)

target_include_directories(pointer_scanner_test PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

add_test(NAME pointer_scanner_test COMMAND pointer_scanner_test)
