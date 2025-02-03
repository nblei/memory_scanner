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
    )
endif()

# Known issue with spdlog
add_compile_options(-Wno-dangling-reference)

# Create the library
# add_library(pointer_scanner
#     src/pointer_scanner.cc
#     src/pointer_scanner_handler.cc
#     src/injector.cc
# )
# 
# target_include_directories(pointer_scanner
#     PUBLIC
#         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
#         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools>
#         $<INSTALL_INTERFACE:include>
# )


# add_library(process_scanner SHARED
#     src/process_scanner.cc
# )
# target_include_directories(process_scanner PUBLIC
#     ${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools
#     )
# 
# target_include_directories(pointerscanner PUBLIC
#     ${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools
# )
# install(TARGETS pointerscanner
#     LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
# )


# Install rules
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/PointerScanner)

# install(TARGETS pointer_scanner
#     EXPORT pointer_scanner-targets
#     LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#     ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
#     RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#     INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
# )
# 
# install(DIRECTORY include/
#     DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
# )

# Export targets
# install(EXPORT pointer_scanner-targets
#     FILE PointerScannerTargets.cmake
#     NAMESPACE PointerScanner::
#     DESTINATION ${INSTALL_CONFIGDIR}
# )

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

FetchContent_MakeAvailable(spdlog cli11)

add_executable(process_monitor
    src/process_scanner.cc
    src/process_monitor.cc
)

target_link_libraries(process_monitor
    PRIVATE
        CLI11::CLI11
        spdlog::spdlog
)

target_include_directories(process_monitor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools>
)

# Testing setup
enable_testing()
add_subdirectory(tests)
