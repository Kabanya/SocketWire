include(${PROJECT_SOURCE_DIR}/cmake/common.cmake)

add_subdirectory(source)

if(NOT EMSCRIPTEN)
  add_subdirectory(tests)
endif()
