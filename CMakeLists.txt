cmake_minimum_required(VERSION 3.28)

project(socketwire LANGUAGES CXX)

# Prevent the user from polluting the root directory with build files
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
    )
endif()

# For enabling debug stuff in "dev" builds, which are RelWithDebInfo.
if (NOT CMAKE_BUILD_TYPE STREQUAL Release)
  set(SOCKETWIRE_DEBUG ON)
else ()
  set(SOCKETWIRE_DEBUG OFF)
endif ()

include("cmake/get_cpm.cmake")
include("cmake/thirdparty.cmake")
include("cmake/get_version.cmake")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Disable C++ module scanning to avoid problems because of cmake 3.28
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

# Check for modules in cmake/clang
# include(CheckCXXCompilerFlag)
# check_cxx_compiler_flag("-fmodules-ts" COMPILER_SUPPORTS_MODULES)
# if(COMPILER_SUPPORTS_MODULES)
#   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmodules-ts")
# else()
#   message(WARNING "The compiler does not support C++ modules. The modules are disabled.")
# endif()

SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(project_options INTERFACE)
add_library(project_warnings INTERFACE)

add_subdirectory(socketwire)


