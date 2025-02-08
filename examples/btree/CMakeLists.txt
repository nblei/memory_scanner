add_executable(btree
  ./btree_harness.cc
)

target_include_directories(btree PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  set_target_properties(btree
      PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
