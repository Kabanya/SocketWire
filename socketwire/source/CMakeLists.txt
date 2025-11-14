cmake_minimum_required(VERSION 3.28)

add_library(SocketWire STATIC
  bit_stream.hpp        bit_stream.cpp
  i_socket.hpp          i_socket.cpp
  posix_udp_socket.cpp
  socket_poller.hpp
  crypto.hpp
)

target_include_directories(SocketWire PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if (TARGET socketwire_crypto)
  target_link_libraries(SocketWire PUBLIC socketwire_crypto)
endif()
