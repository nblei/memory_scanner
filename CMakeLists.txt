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

# Create the library
add_library(pointer_scanner
    src/pointer_scanner.cc
    src/pointer_scanner_handler.cc
    src/injector.cc
)

target_include_directories(pointer_scanner
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools>
        $<INSTALL_INTERFACE:include>
)

# Create example executable
add_executable(scanner_example examples/scanner_example.cc)
target_link_libraries(scanner_example PRIVATE pointer_scanner)
add_library(pointerscanner SHARED
        src/pointer_scanner.cc
        src/injector.cc
    )
target_include_directories(pointerscanner PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/memory_tools
)
install(TARGETS pointerscanner
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)


# Install rules
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/PointerScanner)

install(TARGETS pointer_scanner
    EXPORT pointer_scanner-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export targets
install(EXPORT pointer_scanner-targets
    FILE PointerScannerTargets.cmake
    NAMESPACE PointerScanner::
    DESTINATION ${INSTALL_CONFIGDIR}
)

# Create version file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/PointerScannerConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Testing setup
enable_testing()
add_subdirectory(tests)
