#pragma once

/// Platform-agnostic socket initialization helpers.

namespace socketwire {

void RegisterWindowsSocketFactory();
void RegisterPosixSocketFactory();

/// Initializes the socket subsystem.
///
/// Safe to call multiple times.
bool InitializeSockets();

/// Shuts down the socket subsystem where explicit cleanup is needed.
void ShutdownSockets();

}  // namespace socketwire

// Implementation
#if defined(_WIN32) || defined(_WIN64)
#define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
#define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

namespace socketwire {

inline bool InitializeSockets() {
  static bool initialized = false;
  if (initialized) return true;

#if SOCKETWIRE_PLATFORM_WINDOWS
  register_windows_socket_factory();
#else
  RegisterPosixSocketFactory();
#endif

  initialized = true;
  return true;
}

inline void ShutdownSockets() {
  // On Windows, WSACleanup is called automatically by WSAInitializer
  // destructor. On POSIX, no cleanup needed. This function exists for symmetry
  // and explicit cleanup if needed.
}

}  // namespace socketwire
