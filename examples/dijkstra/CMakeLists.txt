# CMakeLists.txt in examples/dijkstra directory
add_executable(dijkstra
    dijkstra.cc
    dijkstra_harness.cc
    ${CMAKE_SOURCE_DIR}/src/monitor_interface.cc
    ${CMAKE_SOURCE_DIR}/src/command_handler.cc
)

target_link_libraries(dijkstra 
    PRIVATE 
        spdlog::spdlog
)

target_include_directories(dijkstra 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/memory_tools
)

set_target_properties(dijkstra
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Add compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(dijkstra
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wsign-conversion
    )
endif()
