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
  void dispatchAll(const std::vector<SocketEvent>& events, ISocketEventHandler* handler);  PollBackend backendType() const { return backend; }

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

inline SocketPoller::SocketPoller(const SocketPollerConfig& cfg)
{
  fdMap.reserve(cfg.reserveHint);
  initBackend();
}

inline SocketPoller::~SocketPoller()
{
  shutdownBackend();
}

inline void SocketPoller::initBackend()
{
#if SOCKETWIRE_PLATFORM_WINDOWS
  backend = PollBackend::WSAPoll;
  // pollFds will grow dynamically as needed
#elif SOCKETWIRE_PLATFORM_LINUX
  epollFd = ::epoll_create1(0);
  if (epollFd != -1) {
    backend = PollBackend::Epoll;
  } else {
    // Fallback: select
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    selectMaxFd = -1;
    backend = PollBackend::Select;
  }
#elif SOCKETWIRE_PLATFORM_APPLE
  kqueueFd = ::kqueue();
  if (kqueueFd != -1) {
    backend = PollBackend::Kqueue;
  } else {
    // Fallback: select
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    selectMaxFd = -1;
    backend = PollBackend::Select;
  }
#else
  // Fallback: select
  FD_ZERO(&readSet);
  FD_ZERO(&writeSet);
  FD_ZERO(&errorSet);
  selectMaxFd = -1;
  backend = PollBackend::Select;
#endif
}

inline void SocketPoller::shutdownBackend()
{
#if SOCKETWIRE_PLATFORM_WINDOWS
  pollFds.clear();
#elif SOCKETWIRE_PLATFORM_LINUX
  if (backend == PollBackend::Epoll && epollFd != -1) {
    ::close(epollFd);
    epollFd = -1;
  }
#elif SOCKETWIRE_PLATFORM_APPLE
  if (backend == PollBackend::Kqueue && kqueueFd != -1) {
    ::close(kqueueFd);
    kqueueFd = -1;
  }
#endif
  fdMap.clear();
}

inline bool SocketPoller::addSocket(ISocket* socket, bool watchWritable)
{
  if (socket == nullptr) return false;
  int fd = socket->nativeHandle();
  if (fd < 0) return false;
  if (fdMap.find(fd) != fdMap.end()) return true; // already exists
  if (!backendAdd(socket, watchWritable)) return false;
  fdMap.emplace(fd, Watched{socket, watchWritable});
  return true;
}

inline void SocketPoller::removeSocket(ISocket* socket)
{
  if (socket == nullptr) return;
  int fd = socket->nativeHandle();
  if (fd < 0) return;
  auto it = fdMap.find(fd);
  if (it == fdMap.end()) return;
  backendRemove(socket);
  fdMap.erase(it);
}

inline bool SocketPoller::backendAdd(ISocket* socket, bool watchWritable)
{
  int fd = socket->nativeHandle();

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend == PollBackend::WSAPoll) {
    WSAPOLLFD pfd;
    pfd.fd = static_cast<SOCKET>(fd);
    pfd.events = POLLIN;
    if (watchWritable) pfd.events |= POLLOUT;
    pfd.revents = 0;
    pollFds.push_back(pfd);
    return true;
  }
  return false;
#else

#if SOCKETWIRE_PLATFORM_LINUX
  if (backend == PollBackend::Epoll) {
    epoll_event ev{};
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    if (watchWritable) ev.events |= EPOLLOUT;
    if (::epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) != 0)
      return false;
    return true;
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend == PollBackend::Kqueue) {
    struct kevent kev[2];
    int k = 0;
    EV_SET(&kev[k++], fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (watchWritable)
      EV_SET(&kev[k++], fd, EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
    if (::kevent(kqueueFd, kev, k, nullptr, 0, nullptr) != 0)
      return false;
    return true;
  }
#endif

  if (backend == PollBackend::Select) {
    if (fd > selectMaxFd) selectMaxFd = fd;
    FD_SET(fd, &readSet);
    FD_SET(fd, &errorSet);
    if (watchWritable) FD_SET(fd, &writeSet);
    return true;
  }

  return false;
#endif
}

inline void SocketPoller::backendRemove(ISocket* socket) {
  int fd = socket->nativeHandle();

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend == PollBackend::WSAPoll) {
    auto it = std::find_if(pollFds.begin(), pollFds.end(),
      [fd](const WSAPOLLFD& pfd) { return pfd.fd == static_cast<SOCKET>(fd); });
    if (it != pollFds.end()) {
      pollFds.erase(it);
    }
  }
#else

#if SOCKETWIRE_PLATFORM_LINUX
  if (backend == PollBackend::Epoll) {
    ::epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend == PollBackend::Kqueue) {
    struct kevent kev[2];
    int k = 0;
    EV_SET(&kev[k++], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&kev[k++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(kqueueFd, kev, k, nullptr, 0, nullptr);
  }
#endif

  if (backend == PollBackend::Select) {
    FD_CLR(fd, &readSet);
    FD_CLR(fd, &writeSet);
    FD_CLR(fd, &errorSet);
    if (fd == selectMaxFd) {
      // recalculate new maximum
      selectMaxFd = -1;
      for (auto& kv : fdMap) {
        if (kv.first != fd && kv.first > selectMaxFd)
          selectMaxFd = kv.first;
      }
    }
  }
#endif
}

inline std::vector<SocketEvent> SocketPoller::poll(int timeoutMs) {
  return backendPoll(timeoutMs);
}

inline std::vector<SocketEvent> SocketPoller::backendPoll(int timeoutMs) {
  std::vector<SocketEvent> events;
  events.reserve(fdMap.size());

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend == PollBackend::WSAPoll) {
    if (pollFds.empty()) return events;
    
    int waitTime = (timeoutMs < 0) ? -1 : timeoutMs;
    int n = ::WSAPoll(pollFds.data(), static_cast<ULONG>(pollFds.size()), waitTime);
    
    if (n > 0) {
      for (const auto& pfd : pollFds) {
        if (pfd.revents == 0) continue;
        
        int fd = static_cast<int>(pfd.fd);
        auto it = fdMap.find(fd);
        if (it == fdMap.end()) continue;
        
        bool r = (pfd.revents & POLLIN) != 0;
        bool w = (pfd.revents & POLLOUT) != 0;
        bool e = (pfd.revents & POLLERR) != 0;
        bool c = (pfd.revents & POLLHUP) != 0;
        events.push_back(makeEvent(it->second.socket, r, w, e, c));
      }
    }
    return events;
  }
  // Fallback for other backends (shouldn't happen on Windows)
  return events;
#else

#if SOCKETWIRE_PLATFORM_LINUX
  if (backend == PollBackend::Epoll) {
    constexpr int MAX_EVENTS = 64;
    epoll_event evs[MAX_EVENTS];
    int waitTime = (timeoutMs < 0) ? -1 : timeoutMs;
    int n = ::epoll_wait(epollFd, evs, MAX_EVENTS, waitTime);
    for (int i = 0; i < n; ++i) {
      int fd = evs[i].data.fd;
      auto it = fdMap.find(fd);
      if (it == fdMap.end()) continue;
      bool r = (evs[i].events & EPOLLIN) != 0;
      bool w = (evs[i].events & EPOLLOUT) != 0;
      bool e = (evs[i].events & (EPOLLERR | EPOLLHUP)) != 0;
      bool c = (evs[i].events & EPOLLHUP) != 0;
      events.push_back(makeEvent(it->second.socket, r, w, e, c));
    }
    return events;
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend == PollBackend::Kqueue) {
    constexpr int MAX_EVENTS = 64;
    struct kevent kev[MAX_EVENTS];
    struct timespec ts;
    struct timespec* pts = nullptr;
    if (timeoutMs >= 0) {
      ts.tv_sec = timeoutMs / 1000;
      ts.tv_nsec = (timeoutMs % 1000) * 1000000L;
      pts = &ts;
    }
    int n = ::kevent(kqueueFd, nullptr, 0, kev, MAX_EVENTS, pts);
    // In kqueue each event comes separately: READ or WRITE filter
    // We aggregate them into one SocketEvent.
    struct Agg {
      bool r=false, w=false, e=false, c=false;
    };
    std::unordered_map<int, Agg> agg;
    for (int i = 0; i < n; ++i) {
      int fd = static_cast<int>(kev[i].ident);
      auto it = fdMap.find(fd);
      if (it == fdMap.end()) continue;
      Agg& a = agg[fd];
      if (kev[i].filter == EVFILT_READ) a.r = true;
      if (kev[i].filter == EVFILT_WRITE) a.w = true;
      if ((kev[i].flags & EV_ERROR) != 0) a.e = true;
      if ((kev[i].flags & EV_EOF) != 0) a.c = true;
    }
    for (auto& kv : agg) {
      auto it = fdMap.find(kv.first);
      if (it == fdMap.end()) continue;
      events.push_back(makeEvent(it->second.socket,
                                 kv.second.r, kv.second.w,
                                 kv.second.e, kv.second.c));
    }
    return events;
  }
#endif

  if (backend == PollBackend::Select) {
    fd_set rSet = readSet;
    fd_set wSet = writeSet;
    fd_set eSet = errorSet;
    struct timeval tv;
    struct timeval* ptv = nullptr;
    if (timeoutMs >= 0) {
      tv.tv_sec = timeoutMs / 1000;
      tv.tv_usec = (timeoutMs % 1000) * 1000;
      ptv = &tv;
    }
    int n = ::select(selectMaxFd + 1, &rSet, &wSet, &eSet, ptv);
    if (n > 0) {
      for (auto& kv : fdMap) {
        int fd = kv.first;
        bool r = FD_ISSET(fd, &rSet);
        bool w = FD_ISSET(fd, &wSet);
        bool e = FD_ISSET(fd, &eSet);
        // select does not provide explicit closed; can interpret error => closed later.
        events.push_back(makeEvent(kv.second.socket, r, w, e, false));
      }
    }
  }

  return events;
#endif
}

inline void SocketPoller::dispatchReadable(const SocketEvent& ev, ISocketEventHandler* handler) {
  if (handler == nullptr || ev.socket == nullptr || !ev.readable) return;
  // Small read loop:
  for (;;) {
    SocketAddress from;
    std::uint16_t port = 0;
    char buffer[2048];
    SocketResult r = ev.socket->receive(buffer, sizeof(buffer), from, port);
    if (!r.succeeded()) {
      if (r.error != SocketError::WouldBlock) {
        handler->onSocketError(r.error);
      }
      break;
    }
    if (r.bytes <= 0) break;
    handler->onDataReceived(from, port, buffer, static_cast<std::size_t>(r.bytes));
    // If read less than buffer — finish (heuristic)
    if (r.bytes < static_cast<std::ptrdiff_t>(sizeof(buffer))) break;
  }
}

inline void SocketPoller::dispatchAll(const std::vector<SocketEvent>& events, ISocketEventHandler* handler) {
  if (handler == nullptr) return;
  for (auto& e : events) {
    if (e.error) handler->onSocketError(SocketError::System);
    if (e.readable) dispatchReadable(e, handler);
    // writable can be used for send queues (not implemented yet)
    if (e.closed) handler->onSocketClosed();
  }
}

} // namespace socketwire