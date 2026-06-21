add_library(SocketWire STATIC
  bit_stream.hpp
  bit_stream.cpp
  quantization.hpp
  i_socket.hpp
  i_socket.cpp
  socket_poller.hpp
  socket_poller.cpp
  task_queue.hpp
  task_queue.cpp
  thread_pool.hpp
  thread_pool.cpp
  crypto.hpp
  crypto.cpp
  reliable_protocol.hpp
  reliable_protocol.cpp
  reliable_connection.hpp
  reliable_connection.cpp
  connection_manager.hpp
  connection_manager.cpp
  sharded_connection_manager.hpp
  sharded_connection_manager.cpp
  socket_init.hpp
  socket_constants.hpp
  socket_constants.cpp
  socket_address_utils.hpp
  socket_resolver.hpp
  socket_resolver.cpp
)

option(SOCKETWIRE_ENABLE_DARWIN_MSG_X
  "Enable experimental macOS sendmsg_x UDP batching"
  OFF
)

option(SOCKETWIRE_ENABLE_TSAN
  "Build SocketWire with ThreadSanitizer"
  OFF
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

if(SOCKETWIRE_ENABLE_TSAN)
  if(MSVC)
    message(FATAL_ERROR "SOCKETWIRE_ENABLE_TSAN requires Clang or GCC")
  endif()
  target_compile_options(SocketWire PUBLIC
    -fsanitize=thread
    -g
    -O1
    -fno-omit-frame-pointer
  )
  target_link_options(SocketWire PUBLIC -fsanitize=thread)
endif()

if(APPLE AND SOCKETWIRE_ENABLE_DARWIN_MSG_X)
  target_compile_definitions(SocketWire PRIVATE SOCKETWIRE_ENABLE_DARWIN_MSG_X=1)
else()
  target_compile_definitions(SocketWire PRIVATE SOCKETWIRE_ENABLE_DARWIN_MSG_X=0)
endif()

if (TARGET socketwire_crypto)
  target_link_libraries(SocketWire PUBLIC socketwire_crypto)
endif()

if(WIN32)
  target_link_libraries(SocketWire PUBLIC ws2_32 iphlpapi)
endif()

if(EMSCRIPTEN)
  target_link_options(SocketWire PUBLIC -lwebsocket.js)
endif()
