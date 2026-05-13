#pragma once
/// Cross-platform socket I/O multiplexer.
///
/// Uses epoll on Linux, kqueue on macOS/BSD, select as a POSIX fallback, and
/// WSAPoll on Windows. SocketPoller does not own the sockets it watches.

#include <cstdint>
#include <unordered_map>
#include <vector>

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

namespace socketwire {

/// Readiness event for a single socket.
struct SocketEvent {
  ISocket* socket = nullptr;
  bool readable = false;
  bool writable = false;
  bool error = false;
  bool closed = false;
};

/// Active polling backend.
enum class PollBackend : std::uint8_t {
  kEpoll,
  kKqueue,
  kSelect,
  kWsaPoll,
  kStub
};

/// Poller configuration.
struct SocketPollerConfig {
  std::size_t reserveHint = 64;
};

/// Abstraction over epoll, kqueue, select, and WSAPoll.
class SocketPoller {
 public:
  explicit SocketPoller(const SocketPollerConfig& cfg = {});
  ~SocketPoller();

  SocketPoller(const SocketPoller&) = delete;
  SocketPoller& operator=(const SocketPoller&) = delete;

  /// Adds a socket to monitoring.
  bool AddSocket(ISocket* socket, bool watch_writable = false);

  /// Removes a socket from monitoring.
  void RemoveSocket(ISocket* socket);

  /// Polls for events.
  ///
  /// timeout_ms < 0 waits indefinitely, 0 returns immediately, and positive
  /// values wait that many milliseconds.
  std::vector<SocketEvent> Poll(int timeout_ms);

  /// Dispatches a readable event to an ISocketEventHandler.
  void DispatchReadable(const SocketEvent& ev, ISocketEventHandler* handler);

  /// Dispatches all events to an ISocketEventHandler.
  void DispatchAll(const std::vector<SocketEvent>& events,
                   ISocketEventHandler* handler);

  [[nodiscard]] PollBackend BackendType() const;

 private:
  PollBackend backend_ = PollBackend::kStub;

  struct Watched {
    ISocket* socket = nullptr;
    bool watch_writable = false;
  };

  std::unordered_map<int, Watched> fd_map_;  // nativeHandle -> Watched

#if SOCKETWIRE_PLATFORM_WINDOWS
  std::vector<WSAPOLLFD> poll_fds_;  // Windows WSAPoll
#else
  fd_set read_set_{};  // Select fallback (available on all POSIX)
  fd_set write_set_{};
  fd_set error_set_{};
  int select_max_fd_ = -1;

#if SOCKETWIRE_PLATFORM_LINUX
  int epoll_fd_ = -1;  // Linux
#elif SOCKETWIRE_PLATFORM_APPLE
  int kqueue_fd_ = -1;  // macOS/BSD
#endif
#endif

  void InitBackend();
  void ShutdownBackend();

  bool BackendAdd(ISocket* socket, bool watch_writable);
  void BackendRemove(ISocket* socket);

  std::vector<SocketEvent> BackendPoll(int timeout_ms);

  static SocketEvent MakeEvent(ISocket* sock, bool r, bool w, bool e, bool c) {
    SocketEvent ev;
    ev.socket = sock;
    ev.readable = r;
    ev.writable = w;
    ev.error = e;
    ev.closed = c;
    return ev;
  }
};

}  // namespace socketwire
