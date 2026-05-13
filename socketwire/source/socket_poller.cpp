#include "socket_poller.hpp"

#if !SOCKETWIRE_PLATFORM_WINDOWS
#include <unistd.h>

#include <utility>
#endif

namespace socketwire {

SocketPoller::SocketPoller(const SocketPollerConfig& cfg) {
  fdMap.reserve(cfg.reserveHint);
  InitBackend();
}

SocketPoller::~SocketPoller() { ShutdownBackend(); }

void SocketPoller::InitBackend() {
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
    backend = PollBackend::kKqueue;
  } else {
    // Fallback: select
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    selectMaxFd = -1;
    backend = PollBackend::kSelect;
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

void SocketPoller::ShutdownBackend() {
#if SOCKETWIRE_PLATFORM_WINDOWS
  pollFds.clear();
#elif SOCKETWIRE_PLATFORM_LINUX
  if (backend == PollBackend::Epoll && epollFd != -1) {
    ::close(epollFd);
    epollFd = -1;
  }
#elif SOCKETWIRE_PLATFORM_APPLE
  if (backend == PollBackend::kKqueue && kqueueFd != -1) {
    ::close(kqueueFd);
    kqueueFd = -1;
  }
#endif
  fdMap.clear();
}

bool SocketPoller::AddSocket(ISocket* socket, bool watch_writable) {
  if (socket == nullptr) return false;
  int fd = socket->NativeHandle();
  if (fd < 0) return false;
  if (fdMap.find(fd) != fdMap.end()) return true;  // already exists
  if (!BackendAdd(socket, watch_writable)) return false;
  fdMap.emplace(fd, Watched{.socket = socket, .watchWritable = watch_writable});
  return true;
}

void SocketPoller::RemoveSocket(ISocket* socket) {
  if (socket == nullptr) return;
  const int fd = socket->NativeHandle();
  if (fd < 0) return;
  auto it = fdMap.find(fd);
  if (it == fdMap.end()) return;
  BackendRemove(socket);
  fdMap.erase(it);
}

bool SocketPoller::BackendAdd(ISocket* socket, bool watch_writable) {
  const int fd = socket->NativeHandle();

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
    if (::epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) != 0) return false;
    return true;
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend == PollBackend::kKqueue) {
    struct kevent kev[2];
    int k = 0;
    EV_SET(&kev[k++], fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (watch_writable) {
      EV_SET(&kev[k++], fd, EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
    }
    if (::kevent(kqueueFd, kev, k, nullptr, 0, nullptr) != 0) return false;
    return true;
  }
#endif

  if (backend == PollBackend::kSelect) {
    // Guard against FD_SETSIZE overflow — select() is undefined for fd >=
    // FD_SETSIZE
    if (fd >= FD_SETSIZE) return false;
    if (fd > selectMaxFd) selectMaxFd = fd;
    FD_SET(fd, &readSet);
    FD_SET(fd, &errorSet);
    if (watch_writable) FD_SET(fd, &writeSet);
    return true;
  }

  return false;
#endif
}

void SocketPoller::BackendRemove(ISocket* socket) {
  const int fd = socket->NativeHandle();

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend == PollBackend::WSAPoll) {
    auto it = std::find_if(pollFds.begin(), pollFds.end(),
                           [fd](const WSAPOLLFD& pfd) {
                             return pfd.fd == static_cast<SOCKET>(fd);
                           });
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
  if (backend == PollBackend::kKqueue) {
    struct kevent kev[2];
    int k = 0;
    EV_SET(&kev[k++], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&kev[k++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(kqueueFd, kev, k, nullptr, 0, nullptr);
  }
#endif

  if (backend == PollBackend::kSelect) {
    FD_CLR(fd, &readSet);
    FD_CLR(fd, &writeSet);
    FD_CLR(fd, &errorSet);
    if (fd == selectMaxFd) {
      // Recalculate new maximum
      selectMaxFd = -1;
      for (auto& kv : fdMap) {
        if (kv.first != fd && kv.first > selectMaxFd) selectMaxFd = kv.first;
      }
    }
  }
#endif
}

std::vector<SocketEvent> SocketPoller::Poll(int timeout_ms) {
  return BackendPoll(timeout_ms);
}

std::vector<SocketEvent> SocketPoller::BackendPoll(int timeout_ms) {
  std::vector<SocketEvent> events;
  events.reserve(fdMap.size());

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend == PollBackend::WSAPoll) {
    if (pollFds.empty()) return events;

    int waitTime = (timeoutMs < 0) ? -1 : timeoutMs;
    int n =
        ::WSAPoll(pollFds.data(), static_cast<ULONG>(pollFds.size()), waitTime);

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
  if (backend == PollBackend::kKqueue) {
    constexpr int max_events = 64;
    struct kevent kev[max_events];
    struct timespec ts{};
    const struct timespec* pts = nullptr;
    if (timeout_ms >= 0) {
      ts.tv_sec = timeout_ms / 1000;
      ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
      pts = &ts;
    }
    const int n = ::kevent(kqueueFd, nullptr, 0, kev, max_events, pts);
    // Aggregate READ/WRITE events per fd into a single SocketEvent.
    struct Agg {
      bool r = false, w = false, e = false, c = false;
    };
    std::unordered_map<int, Agg> agg;
    for (int i = 0; i < n; ++i) {
      const int fd = static_cast<int>(kev[i].ident);
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
      events.push_back(MakeEvent(it->second.socket, kv.second.r, kv.second.w,
                                 kv.second.e, kv.second.c));
    }
    return events;
  }
#endif

  if (backend == PollBackend::kSelect) {
    fd_set r_set = readSet;
    fd_set w_set = writeSet;
    fd_set e_set = errorSet;
    struct timeval tv{};
    struct timeval* ptv = nullptr;
    if (timeout_ms >= 0) {
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;
      ptv = &tv;
    }
    const int n = ::select(selectMaxFd + 1, &r_set, &w_set, &e_set, ptv);
    if (n > 0) {
      for (auto& kv : fdMap) {
       const int fd = kv.first;
       const bool r = FD_ISSET(fd, &r_set) != 0;
       const bool w = FD_ISSET(fd, &w_set) != 0;
       const bool e = FD_ISSET(fd, &e_set) != 0;
        events.push_back(MakeEvent(kv.second.socket, r, w, e, false));
      }
    }
  }

  return events;
#endif
}

void SocketPoller::DispatchReadable(const SocketEvent& ev,
                                    ISocketEventHandler* handler) {
  if (handler == nullptr || ev.socket == nullptr || !ev.readable) return;
  for (;;) {
    SocketAddress from;
    std::uint16_t port = 0;
    char buffer[2048];
    const SocketResult r = ev.socket->Receive(buffer, sizeof(buffer), from, port);
    if (!r.Succeeded()) {
      if (r.error != SocketError::kWouldBlock) {
        handler->OnSocketError(r.error);
      }
      break;
    }
    if (r.bytes <= 0) break;
    handler->OnDataReceived(from, port, buffer,
                            static_cast<std::size_t>(r.bytes));
    // If read less than buffer — finish (heuristic)
    if (std::cmp_less(r.bytes, sizeof(buffer))) break;
  }
}

void SocketPoller::DispatchAll(const std::vector<SocketEvent>& events,
                               ISocketEventHandler* handler) {
  if (handler == nullptr) return;
  for (auto& e : events) {
    if (e.error) handler->OnSocketError(SocketError::kSystem);
    if (e.readable) DispatchReadable(e, handler);
    // writable can be used for send queues (not implemented yet)
    if (e.closed) handler->OnSocketClosed();
  }
}

PollBackend SocketPoller::BackendType() const { return backend; }

}  // namespace socketwire
