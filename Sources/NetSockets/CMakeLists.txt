cmake_minimum_required(VERSION 3.28)

add_library(NetSocketLib STATIC
  NetSocket.cpp
  NetSocket.h
)

target_include_directories(NetSocketLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})