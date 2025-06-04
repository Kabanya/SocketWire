cmake_minimum_required(VERSION 3.28)

project(Framework-Networked)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(project_options INTERFACE)
add_library(project_warnings INTERFACE)

add_subdirectory(Sources)
add_subdirectory(Samples)