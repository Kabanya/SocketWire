cmake_minimum_required(VERSION 3.28)

add_library(SocketWire STATIC
  NetSocket.cpp    NetSocket.h
  BitStream.cpp    BitStream.h
)

target_include_directories(SocketWire PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
