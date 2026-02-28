#pragma once
/*
  SocketPoller — event system / I/O multiplexing for cross-platform network layer.

  Goals:
  - Poll multiple sockets with minimal system calls.
  - Provide unified events: Readable / Writable / Error / Closed.
  - Integration with ISocket and ISocketEventHandler (from i_socket.hpp).

  Backend implementations:
  - Linux: epoll
  - macOS / BSD: kqueue
  - Fallback (any POSIX): select (less efficient, but works)
  - Windows: stubs only for now (can add WSAPoll / IOCP later).

  Usage (example):

    socketwire::SocketPoller poller;
    poller.addSocket(mySocketPtr);
    auto events = poller.poll(10); // wait up to 10 ms
    for (auto& e : events) {
      if (e.readable) {
        // Can call socket->receive(...) or poller.dispatch(e, handler);
      }
    }

  For convenience, there is a dispatch method that calls onDataReceived inside ISocketEventHandler.
  It performs non-blocking reads until the buffer is drained (similar to poll() in PosixUDPSocket).

  IMPORTANT: The class does not own sockets — you are responsible for their lifetime.
*/

#include <cstdint>
#include <vector>
#include <unordered_map>

#include "i_socket.hpp"

#if defined(_WIN32) || defined(_WIN64)
  #define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
  #define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

#if SOCKETWIRE_PLATFORM_WINDOWS
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if defined(__linux__)
    #define SOCKETWIRE_PLATFORM_LINUX 1
  #else
    #define SOCKETWIRE_PLATFORM_LINUX 0
  #endif
  #if defined(__APPLE__)
    #define SOCKETWIRE_PLATFORM_APPLE 1
  #else
    #define SOCKETWIRE_PLATFORM_APPLE 0
  #endif
  #if SOCKETWIRE_PLATFORM_LINUX
    #include <sys/epoll.h>
  #elif SOCKETWIRE_PLATFORM_APPLE
    #include <sys/event.h>
    #include <sys/time.h>
  #endif
  #include <sys/select.h>
  #include <unistd.h>
#endif

namespace socketwire
{

// Event structure for a single socket.
struct SocketEvent
{
  ISocket* socket = nullptr;
  bool readable = false;
  bool writable = false;
  bool error = false;
  bool closed = false;
};

// Backend type
enum class PollBackend : std::uint8_t
{
  Epoll,
  Kqueue,
  Select,
  WSAPoll,
  Stub
};

/*
  Poller configuration.
  reserveHint — estimated number of sockets (to minimize reallocations).
*/
struct SocketPollerConfig {
  std::size_t reserveHint = 64;
};


// SocketPoller — abstraction over epoll/kqueue/select.
class SocketPoller
{
public:
  explicit SocketPoller(const SocketPollerConfig& cfg = {});
  ~SocketPoller();

  SocketPoller(const SocketPoller&) = delete;
  SocketPoller& operator=(const SocketPoller&) = delete;

  // Add socket to monitoring. watchWritable=true — also monitor write readiness.
  bool addSocket(ISocket* socket, bool watchWritable = false);

  // Remove socket
  void removeSocket(ISocket* socket);

  /* Poll for events.
    timeoutMs < 0 => wait indefinitely (blocking mode).
    timeoutMs == 0 => immediate poll (non-block).
    timeoutMs > 0 => wait that many milliseconds.
  */
  std::vector<SocketEvent> poll(int timeoutMs);

  /* Fast dispatch of readable events to handler:
    - performs receive() in a loop while socket yields data
    - calls onDataReceived
    - errors -> onSocketError
  */
  void dispatchReadable(const SocketEvent& ev, ISocketEventHandler* handler);

  // Utility: for all events at once.
  void dispatchAll(const std::vector<SocketEvent>& events, ISocketEventHandler* handler);

  PollBackend backendType() const;

private:
  PollBackend backend = PollBackend::Stub;

  struct Watched {
    ISocket* socket = nullptr;
    bool watchWritable = false;
  };

  std::unordered_map<int, Watched> fdMap; // nativeHandle -> Watched

#if SOCKETWIRE_PLATFORM_WINDOWS
  std::vector<WSAPOLLFD> pollFds; // Windows WSAPoll
#else
  fd_set readSet;     // Select fallback (available on all POSIX)
  fd_set writeSet;
  fd_set errorSet;
  int selectMaxFd = -1;
  
  #if SOCKETWIRE_PLATFORM_LINUX
    int epollFd = -1;   // Linux
  #elif SOCKETWIRE_PLATFORM_APPLE
    int kqueueFd = -1;  // macOS/BSD
  #endif
#endif

  void initBackend();
  void shutdownBackend();

  bool backendAdd(ISocket* socket, bool watchWritable);
  void backendRemove(ISocket* socket);

  std::vector<SocketEvent> backendPoll(int timeoutMs);

  // Helpers
  static SocketEvent makeEvent(ISocket* sock, bool r, bool w, bool e, bool c) {
    SocketEvent ev;
    ev.socket = sock;
    ev.readable = r;
    ev.writable = w;
    ev.error = e;
    ev.closed = c;
    return ev;
  }
};

} // namespace socketwire
