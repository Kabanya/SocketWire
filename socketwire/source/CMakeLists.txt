cmake_minimum_required(VERSION 3.28)

add_library(SocketWire STATIC
  net_socket.cpp    net_socket.hpp
  bit_stream.cpp    bit_stream.hpp
  i_socket.cpp      i_socket.hpp
)

target_include_directories(SocketWire PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
