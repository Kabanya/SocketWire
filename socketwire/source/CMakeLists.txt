add_library(SocketWire STATIC
  bit_stream.hpp
  bit_stream.cpp
  i_socket.hpp
  i_socket.cpp
  socket_poller.hpp
  socket_poller.cpp
  crypto.hpp
  crypto.cpp
  reliable_protocol.hpp
  reliable_protocol.cpp
  reliable_connection.hpp
  reliable_connection.cpp
  connection_manager.hpp
  connection_manager.cpp
  socket_init.hpp
  socket_constants.hpp
  socket_constants.cpp
  socket_address_utils.hpp
)

if(EMSCRIPTEN)
  target_sources(SocketWire PRIVATE emscripten_websocket.cpp)
elseif(WIN32)
  target_sources(SocketWire PRIVATE windows_udp_socket.cpp)
else()
  target_sources(SocketWire PRIVATE posix_udp_socket.cpp)
endif()

target_include_directories(SocketWire PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(SocketWire PUBLIC cxx_std_23)

if (TARGET socketwire_crypto)
  target_link_libraries(SocketWire PUBLIC socketwire_crypto)
endif()

if(EMSCRIPTEN)
  target_link_options(SocketWire PUBLIC -lwebsocket.js)
endif()
