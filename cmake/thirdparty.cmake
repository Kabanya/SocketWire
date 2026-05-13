# Google Test for unit testing
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  VERSION 1.17.0
  OPTIONS
    "INSTALL_GTEST OFF"
    "gtest_force_shared_crt ON"
)

option(SOCKETWIRE_USE_LIBSODIUM "Enable libsodium crypto library" ON)
set(SOCKETWIRE_FETCH_LIBSODIUM ON CACHE BOOL "Download and build libsodium when SOCKETWIRE_USE_LIBSODIUM is ON and no system libsodium is found")
set(SOCKETWIRE_LIBSODIUM_VERSION "1.0.22" CACHE STRING "libsodium version to download when SOCKETWIRE_FETCH_LIBSODIUM is ON")
set(SOCKETWIRE_LIBSODIUM_URL
  "https://download.libsodium.org/libsodium/releases/libsodium-${SOCKETWIRE_LIBSODIUM_VERSION}.tar.gz"
  CACHE STRING
  "libsodium release tarball URL"
)
set(SOCKETWIRE_LIBSODIUM_SHA256
  "adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
  CACHE STRING
  "SHA256 for SOCKETWIRE_LIBSODIUM_URL"
)

if(SOCKETWIRE_USE_LIBSODIUM)
  add_library(socketwire_crypto INTERFACE)
  find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
  find_library(SODIUM_LIBRARY NAMES sodium libsodium)

  if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    if(NOT SOCKETWIRE_FETCH_LIBSODIUM)
      message(FATAL_ERROR "SOCKETWIRE_USE_LIBSODIUM is ON, but libsodium was not found. Install libsodium, set SODIUM_INCLUDE_DIR/SODIUM_LIBRARY, or enable SOCKETWIRE_FETCH_LIBSODIUM.")
    endif()

    if(WIN32)
      message(FATAL_ERROR "SOCKETWIRE_FETCH_LIBSODIUM is not implemented for Windows yet. Install libsodium manually or set SODIUM_INCLUDE_DIR and SODIUM_LIBRARY.")
    endif()

    include(ExternalProject)
    find_program(SOCKETWIRE_MAKE_PROGRAM NAMES gmake make REQUIRED)

    set(SOCKETWIRE_LIBSODIUM_PREFIX "${CMAKE_BINARY_DIR}/_deps/libsodium")
    set(SOCKETWIRE_LIBSODIUM_INSTALL_DIR "${SOCKETWIRE_LIBSODIUM_PREFIX}/install")
    set(SODIUM_INCLUDE_DIR "${SOCKETWIRE_LIBSODIUM_INSTALL_DIR}/include")
    set(SODIUM_LIBRARY "${SOCKETWIRE_LIBSODIUM_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}sodium${CMAKE_STATIC_LIBRARY_SUFFIX}")

    file(MAKE_DIRECTORY "${SODIUM_INCLUDE_DIR}")
    file(MAKE_DIRECTORY "${SOCKETWIRE_LIBSODIUM_INSTALL_DIR}/lib")

    ExternalProject_Add(socketwire_libsodium_external
      URL "${SOCKETWIRE_LIBSODIUM_URL}"
      URL_HASH "SHA256=${SOCKETWIRE_LIBSODIUM_SHA256}"
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE
      PREFIX "${SOCKETWIRE_LIBSODIUM_PREFIX}"
      INSTALL_DIR "${SOCKETWIRE_LIBSODIUM_INSTALL_DIR}"
      BUILD_IN_SOURCE TRUE
      BUILD_BYPRODUCTS "${SODIUM_LIBRARY}"
      CONFIGURE_COMMAND <SOURCE_DIR>/configure
        --prefix=<INSTALL_DIR>
        --disable-shared
        --enable-static
        --with-pic
      BUILD_COMMAND "${SOCKETWIRE_MAKE_PROGRAM}"
      INSTALL_COMMAND "${SOCKETWIRE_MAKE_PROGRAM}" install
      TEST_COMMAND ""
    )

    add_library(socketwire_libsodium STATIC IMPORTED GLOBAL)
    set_target_properties(socketwire_libsodium PROPERTIES
      IMPORTED_LOCATION "${SODIUM_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
    add_dependencies(socketwire_libsodium socketwire_libsodium_external)

    target_link_libraries(socketwire_crypto INTERFACE socketwire_libsodium)
    message(STATUS "SOCKETWIRE_USE_LIBSODIUM is ON — libsodium will be downloaded and built from ${SOCKETWIRE_LIBSODIUM_URL}")
  else()
    message(STATUS "SOCKETWIRE_USE_LIBSODIUM is ON — using libsodium")
    target_include_directories(socketwire_crypto INTERFACE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(socketwire_crypto INTERFACE ${SODIUM_LIBRARY})
  endif()

  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=1)
else()
  message(STATUS "SOCKETWIRE_USE_LIBSODIUM is OFF — building without libsodium support")
  message(STATUS "Crypto features are disabled. libsodium is enabled by default; keep this only for explicit no-crypto builds.")
  add_library(socketwire_crypto INTERFACE)
  target_compile_definitions(socketwire_crypto INTERFACE SOCKETWIRE_HAVE_LIBSODIUM=0)
endif()
