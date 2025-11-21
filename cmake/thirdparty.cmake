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
  message(STATUS "SOCKETWIRE_USE_LIBSODIUM is ON, but libsodium building is not configured")
  message(STATUS "Ensure libsodium is installed separately or provide a CMake build")
  
  add_library(socketwire_crypto INTERFACE)
  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=0)
else()
  message(STATUS "SOCKETWIRE_USE_LIBSODIUM is OFF — building without libsodium support")
  message(STATUS "Crypto features will be disabled. For crypto support, install libsodium and set -DSOCKETWIRE_USE_LIBSODIUM=ON")
  add_library(socketwire_crypto INTERFACE)
  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=0)
endif()
