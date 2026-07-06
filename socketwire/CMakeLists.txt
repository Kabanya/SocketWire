include(${PROJECT_SOURCE_DIR}/cmake/common.cmake)

add_subdirectory(source)

if(SOCKETWIRE_BUILD_TESTS AND NOT EMSCRIPTEN)
  add_subdirectory(tests)
endif()
