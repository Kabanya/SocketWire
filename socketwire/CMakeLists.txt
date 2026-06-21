include(${PROJECT_SOURCE_DIR}/cmake/common.cmake)

add_subdirectory(source)

if(NOT EMSCRIPTEN)
  add_subdirectory(tests)

  add_executable(SocketWireLoad
    tools/socketwire_load.cpp
  )

  target_link_libraries(SocketWireLoad PRIVATE SocketWire)
endif()
