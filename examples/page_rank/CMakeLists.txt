add_executable(pagerank
  pagerank.cc
  pagerank_harness.cc
  )

target_include_directories(pagerank PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  set_target_properties(pagerank
      PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  )
