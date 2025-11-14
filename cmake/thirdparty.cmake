cmake_minimum_required(VERSION 3.28)

# Google Test for unit testing
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  VERSION 1.17.0
  OPTIONS
    "INSTALL_GTEST OFF"
    "gtest_force_shared_crt ON"
)

# # libsodium for cryptography
# CPMAddPackage(
#   NAME libsodium
#   GITHUB_REPOSITORY jedisct1/libsodium
#   GIT_TAG 1.0.20-RELEASE
#   OPTIONS
#     "SODIUM_MINIMAL ON"
# )

# if(libsodium_ADDED)
#   # Since CPM doesn't build libsodium properly, define it manually
#   add_library(libsodium STATIC IMPORTED)
#   set_target_properties(libsodium PROPERTIES
#     IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/_deps/libsodium-build/libsodium.a
#     INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/_deps/libsodium-build/include
#   )
#   add_library(socketwire_crypto INTERFACE)
#   target_link_libraries(socketwire_crypto INTERFACE libsodium)
#   target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=1)
# else()
#   message(WARNING "libsodium not found; crypto will be disabled")
# endif()
