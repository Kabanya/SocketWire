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

# libsodium for cryptography
CPMAddPackage(
  NAME libsodium
  GITHUB_REPOSITORY jedisct1/libsodium
  GIT_TAG 1.0.20-RELEASE
  OPTIONS
    "SODIUM_MINIMAL ON"
)

if(libsodium_ADDED)
  include(ExternalProject)

  set(LIBSODIUM_BUILD_DIR ${CMAKE_BINARY_DIR}/_deps/libsodium-build)
  set(LIBSODIUM_SOURCE_DIR ${CMAKE_BINARY_DIR}/_deps/libsodium-src)

  ExternalProject_Add(
    libsodium_external
    SOURCE_DIR ${LIBSODIUM_SOURCE_DIR}
    BINARY_DIR ${LIBSODIUM_BUILD_DIR}
    CONFIGURE_COMMAND ${LIBSODIUM_SOURCE_DIR}/configure --prefix=${LIBSODIUM_BUILD_DIR} --enable-minimal
    BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL}
    INSTALL_COMMAND make install
    BUILD_BYPRODUCTS ${LIBSODIUM_BUILD_DIR}/lib/libsodium.a
  )

  # Define the imported library
  add_library(libsodium STATIC IMPORTED)
  set_target_properties(libsodium PROPERTIES
    IMPORTED_LOCATION ${LIBSODIUM_BUILD_DIR}/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIBSODIUM_BUILD_DIR}/include
  )
  add_dependencies(libsodium libsodium_external)

  add_library(socketwire_crypto INTERFACE)
  target_link_libraries(socketwire_crypto INTERFACE libsodium)
  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=1)
else()
  message(WARNING "libsodium not found; crypto will be disabled")
endif()
