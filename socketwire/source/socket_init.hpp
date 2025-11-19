#pragma once

/*
  Platform-agnostic socket initialization helper.

  This header provides a unified way to initialize the socket subsystem
  across different platforms (POSIX/Windows).

  Usage:
    // At application startup:
    socketwire::initialize_sockets();

    // At application shutdown (optional, automatic on destruction):
    socketwire::shutdown_sockets();
*/

namespace socketwire
{

// Forward declarations
void register_windows_socket_factory();
void register_posix_socket_factory();

/*
  Initialize the socket subsystem.
  - On Windows: Registers Windows socket factory and initializes WSA.
  - On POSIX: Registers POSIX socket factory.

  This function is safe to call multiple times (idempotent).
  Returns true on success, false on failure.
*/
bool initialize_sockets();

/*
  Shutdown the socket subsystem.
  - On Windows: Cleanup is handled automatically by WSAInitializer destructor.
  - On POSIX: No-op.

  This function is optional as cleanup happens automatically,
  but can be called explicitly for deterministic resource cleanup.
*/
void shutdown_sockets();

} // namespace socketwire

// Implementation
#if defined(_WIN32) || defined(_WIN64)
  #define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
  #define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

namespace socketwire
{

inline bool initialize_sockets()
{
  static bool initialized = false;
  if (initialized)
    return true;

#if SOCKETWIRE_PLATFORM_WINDOWS
  register_windows_socket_factory();
#else
  register_posix_socket_factory();
#endif

  initialized = true;
  return true;
}

inline void shutdown_sockets()
{
  // On Windows, WSACleanup is called automatically by WSAInitializer destructor.
  // On POSIX, no cleanup needed.
  // This function exists for symmetry and explicit cleanup if needed.
}

} // namespace socketwire