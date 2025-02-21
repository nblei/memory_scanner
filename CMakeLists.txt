cmake_minimum_required(VERSION 3.14)
project(memory_tools 
        VERSION 1.0
        DESCRIPTION "Tools for analyzing process memory and pointers"
        LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wconversion
        -Wsign-conversion
        -Wshadow
    )
endif()

# Known issue with spdlog
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-Wno-dangling-reference)
endif()

# Install rules
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/PointerScanner)

# Create version file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/PointerScannerConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

include(FetchContent)

# Fetch spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.13.0
)

# Fetch CLI11
FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.3.2
)

add_custom_target(criu_build
    COMMAND make
    WORKING_DIRECTORY ${criu_SOURCE_DIR}
    COMMENT "Building CRIU from source"
)

FetchContent_MakeAvailable(spdlog cli11)

find_library(CRIU_LIBRARY criu)
if(NOT CRIU_LIBRARY)
    message(FATAL_ERROR "CRIU library not found")
endif()

add_executable(process_monitor
    ./src/process_manager.cc
    ./src/monitor_interface.cc
    ./src/process_monitor.cc
    ./src/attach_guard.cc
    ./src/cli.cc
    ./src/global_state.cc
    ./src/command_handler.cc
    ./src/monitor_controller.cc
)

target_link_libraries(process_monitor
    PRIVATE
        CLI11::CLI11
        spdlog::spdlog
        ${CRIU_LIBRARY}
)

target_include_directories(process_monitor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools>
    PRIVATE
        ${criu_SOURCE_DIR}/include
)

add_subdirectory(examples)

# Find Doxygen
find_package(Doxygen REQUIRED)

# Check if Dot is installed
if(NOT DOXYGEN_DOT_FOUND) 
    message(WARNING "Graphviz/Dot not found - UML diagrams will not be generated")
endif()

# Configure Doxyfile
set(DOXYGEN_GENERATE_HTML YES)
set(DOXYGEN_GENERATE_XML YES)
set(DOXYGEN_CLASS_DIAGRAMS YES)
set(DOXYGEN_CLASS_GRAPH YES)
set(DOXYGEN_COLLABORATION_GRAPH YES)
set(DOXYGEN_INCLUDE_GRAPH YES)
set(DOXYGEN_INCLUDED_BY_GRAPH YES)
set(DOXYGEN_CALL_GRAPH YES)
set(DOXYGEN_CALLER_GRAPH YES)
set(DOXYGEN_EXTRACT_ALL YES)
set(DOXYGEN_EXTRACT_PRIVATE YES)
set(DOXYGEN_EXTRACT_STATIC YES)
set(DOXYGEN_UML_LOOK YES)
set(DOXYGEN_HAVE_DOT ${DOXYGEN_DOT_FOUND})
set(DOXYGEN_DOT_GRAPH_MAX_NODES 100)

# Setup doxygen target that creates documentation
doxygen_add_docs(docs 
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/include/memory_tools
    COMMENT "Generating documentation with Doxygen"
)
