add_library(SocketWire STATIC
  bit_stream.hpp
  bit_stream.cpp
  i_socket.hpp
  i_socket.cpp
  socket_poller.hpp
  socket_poller.cpp
  crypto.hpp
  crypto.cpp
  reliable_connection.hpp
  reliable_connection.cpp
  socket_init.hpp
  socket_constants.hpp
  socket_constants.cpp
  socket_address_utils.hpp
)

if(WIN32)
  target_sources(SocketWire PRIVATE windows_udp_socket.cpp)
else()
  target_sources(SocketWire PRIVATE posix_udp_socket.cpp)
endif()

target_include_directories(SocketWire PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if (TARGET socketwire_crypto)
  target_link_libraries(SocketWire PUBLIC socketwire_crypto)
endif()
