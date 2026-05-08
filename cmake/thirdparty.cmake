# Google Test for unit testing
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  VERSION 1.17.0
  OPTIONS
    "INSTALL_GTEST OFF"
    "gtest_force_shared_crt ON"
)

if(NOT DEFINED SOCKETWIRE_USE_LIBSODIUM)
  set(SOCKETWIRE_USE_LIBSODIUM OFF CACHE BOOL "Enable libsodium crypto library" FORCE)
endif()

if(SOCKETWIRE_USE_LIBSODIUM)
  add_library(socketwire_crypto INTERFACE)
  find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
  find_library(SODIUM_LIBRARY NAMES sodium libsodium)

  if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "SOCKETWIRE_USE_LIBSODIUM is ON, but libsodium was not found. Install libsodium or set SODIUM_INCLUDE_DIR and SODIUM_LIBRARY.")
  endif()

  message(STATUS "SOCKETWIRE_USE_LIBSODIUM is ON — using libsodium")
  target_include_directories(socketwire_crypto INTERFACE ${SODIUM_INCLUDE_DIR})
  target_link_libraries(socketwire_crypto INTERFACE ${SODIUM_LIBRARY})
  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=1)
else()
  message(STATUS "SOCKETWIRE_USE_LIBSODIUM is OFF — building without libsodium support")
  message(STATUS "Crypto features will be disabled. For crypto support, install libsodium and set -DSOCKETWIRE_USE_LIBSODIUM=ON")
  add_library(socketwire_crypto INTERFACE)
  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=0)
endif()
