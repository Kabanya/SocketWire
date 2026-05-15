#pragma once

/// Platform-agnostic socket initialization helpers.

namespace socketwire {

void RegisterEmscriptenSocketFactory();
void RegisterWindowsSocketFactory();
void RegisterPosixSocketFactory();

/// Initializes the socket subsystem.
///
/// Safe to call multiple times.
void InitializeSockets();

}  // namespace socketwire

// Implementation
#if defined(__EMSCRIPTEN__)
#define SOCKETWIRE_PLATFORM_EMSCRIPTEN 1
#else
#define SOCKETWIRE_PLATFORM_EMSCRIPTEN 0
#endif

#if defined(_WIN32) || defined(_WIN64)
#define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
#define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

namespace socketwire {

inline void InitializeSockets() {
  static bool initialized = false;
  if (initialized) return;

#if SOCKETWIRE_PLATFORM_EMSCRIPTEN
  RegisterEmscriptenSocketFactory();
#elif SOCKETWIRE_PLATFORM_WINDOWS
  RegisterWindowsSocketFactory();
#else
  RegisterPosixSocketFactory();
#endif

  initialized = true;
}

}  // namespace socketwire
