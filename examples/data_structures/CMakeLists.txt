# Collect all .cc files in the current directory
# Fetch CLI11
FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.3.2
)
FetchContent_MakeAvailable(cli11)

file(GLOB CC_SOURCES "*.cc") # Create an executable for each source file
foreach(source_file ${CC_SOURCES})
    # Get the filename without extension
    get_filename_component(filename ${source_file} NAME_WE)

    # Create executable with the same name as the source file
    add_executable(${filename} ${source_file})
    # target_compile_options(${filename} PRIVATE -Wno-error=conversion -Wno-error=sign-conversion -Wno-error=unused-variable)
    target_link_libraries(${filename}
        PRIVATE
            CLI11::CLI11
    )
    
    # Optional: Set output directory for all executables
    set_target_properties(${filename}
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endforeach()

