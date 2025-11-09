cmake_minimum_required(VERSION 3.28)

add_library(SocketWire STATIC
  bit_stream.cpp        bit_stream.hpp
  i_socket.cpp          i_socket.hpp
  posix_udp_socket.cpp
  socket_poller.hpp
)

target_include_directories(SocketWire PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
