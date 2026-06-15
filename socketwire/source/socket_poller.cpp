#include "socket_poller.hpp"

#include <algorithm>
#include <utility>

#if !SOCKETWIRE_PLATFORM_WINDOWS
#include <unistd.h>
#endif

namespace socketwire {

SocketPoller::SocketPoller(const SocketPollerConfig& cfg) {
  fd_map_.reserve(cfg.reserveHint);
  InitBackend();
}

SocketPoller::~SocketPoller() { ShutdownBackend(); }

void SocketPoller::InitBackend() {
#if SOCKETWIRE_PLATFORM_WINDOWS
  backend_ = PollBackend::kWsaPoll;
#elif SOCKETWIRE_PLATFORM_LINUX
  epoll_fd_ = ::epoll_create1(0);
  if (epoll_fd_ != -1) {
    backend_ = PollBackend::kEpoll;
  } else {
    FD_ZERO(&read_set_);
    FD_ZERO(&write_set_);
    FD_ZERO(&error_set_);
    select_max_fd_ = -1;
    backend_ = PollBackend::kSelect;
  }
#elif SOCKETWIRE_PLATFORM_APPLE
  kqueue_fd_ = ::kqueue();
  if (kqueue_fd_ != -1) {
    backend_ = PollBackend::kKqueue;
  } else {
    FD_ZERO(&read_set_);
    FD_ZERO(&write_set_);
    FD_ZERO(&error_set_);
    select_max_fd_ = -1;
    backend_ = PollBackend::kSelect;
  }
#else
  FD_ZERO(&read_set_);
  FD_ZERO(&write_set_);
  FD_ZERO(&error_set_);
  select_max_fd_ = -1;
  backend_ = PollBackend::kSelect;
#endif
}

void SocketPoller::ShutdownBackend() {
#if SOCKETWIRE_PLATFORM_WINDOWS
  poll_fds_.clear();
#elif SOCKETWIRE_PLATFORM_LINUX
  if (backend_ == PollBackend::kEpoll && epoll_fd_ != -1) {
    ::close(epoll_fd_);
    epoll_fd_ = -1;
  }
#elif SOCKETWIRE_PLATFORM_APPLE
  if (backend_ == PollBackend::kKqueue && kqueue_fd_ != -1) {
    ::close(kqueue_fd_);
    kqueue_fd_ = -1;
  }
#endif
  fd_map_.clear();
}

bool SocketPoller::AddSocket(ISocket* socket, bool watch_writable) {
  if (socket == nullptr) return false;
  int fd = socket->NativeHandle();
  if (fd < 0) return false;
  if (fd_map_.find(fd) != fd_map_.end()) return true;
  if (!BackendAdd(socket, watch_writable)) return false;
  fd_map_.emplace(fd,
                  Watched{.socket = socket, .watch_writable = watch_writable});
  return true;
}

void SocketPoller::RemoveSocket(ISocket* socket) {
  if (socket == nullptr) return;
  const int fd = socket->NativeHandle();
  if (fd < 0) return;
  auto it = fd_map_.find(fd);
  if (it == fd_map_.end()) return;
  BackendRemove(socket);
  fd_map_.erase(it);
}

bool SocketPoller::BackendAdd(ISocket* socket, bool watch_writable) {
  const int fd = socket->NativeHandle();

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend_ == PollBackend::kWsaPoll) {
    WSAPOLLFD pfd;
    pfd.fd = static_cast<SOCKET>(fd);
    pfd.events = POLLIN;
    if (watch_writable) pfd.events |= POLLOUT;
    pfd.revents = 0;
    poll_fds_.push_back(pfd);
    return true;
  }
  return false;
#else

#if SOCKETWIRE_PLATFORM_LINUX
  if (backend_ == PollBackend::kEpoll) {
    epoll_event ev{};
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    if (watch_writable) ev.events |= EPOLLOUT;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) != 0) return false;
    return true;
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend_ == PollBackend::kKqueue) {
    struct kevent kev[2];
    int k = 0;
    EV_SET(&kev[k++], fd, EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (watch_writable) {
      EV_SET(&kev[k++], fd, EVFILT_WRITE, EV_ADD, 0, 0, nullptr);
    }
    if (::kevent(kqueue_fd_, kev, k, nullptr, 0, nullptr) != 0) return false;
    return true;
  }
#endif

  if (backend_ == PollBackend::kSelect) {
    // select() is undefined for descriptors outside FD_SETSIZE.
    if (fd >= FD_SETSIZE) return false;
    if (fd > select_max_fd_) select_max_fd_ = fd;
    FD_SET(fd, &read_set_);
    FD_SET(fd, &error_set_);
    if (watch_writable) FD_SET(fd, &write_set_);
    return true;
  }

  return false;
#endif
}

void SocketPoller::BackendRemove(ISocket* socket) {
  const int fd = socket->NativeHandle();

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend_ == PollBackend::kWsaPoll) {
    auto it = std::find_if(
      poll_fds_.begin(), poll_fds_.end(),
      [fd](const WSAPOLLFD& pfd) { return pfd.fd == static_cast<SOCKET>(fd); });
    if (it != poll_fds_.end()) {
      poll_fds_.erase(it);
    }
  }
#else

#if SOCKETWIRE_PLATFORM_LINUX
  if (backend_ == PollBackend::kEpoll) {
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend_ == PollBackend::kKqueue) {
    struct kevent kev[2];
    int k = 0;
    EV_SET(&kev[k++], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&kev[k++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(kqueue_fd_, kev, k, nullptr, 0, nullptr);
  }
#endif

  if (backend_ == PollBackend::kSelect) {
    FD_CLR(fd, &read_set_);
    FD_CLR(fd, &write_set_);
    FD_CLR(fd, &error_set_);
    if (fd == select_max_fd_) {
      select_max_fd_ = -1;
      for (auto& kv : fd_map_) {
        if (kv.first != fd && kv.first > select_max_fd_) {
          select_max_fd_ = kv.first;
        }
      }
    }
  }
#endif
}

std::vector<SocketEvent> SocketPoller::Poll(int timeout_ms) {
  std::vector<SocketEvent> events;
  PollInto(events, timeout_ms);
  return events;
}

void SocketPoller::PollInto(std::vector<SocketEvent>& events,
                            int timeout_ms) {
  BackendPoll(events, timeout_ms);
}

void SocketPoller::BackendPoll(std::vector<SocketEvent>& events,
                               int timeout_ms) {
  events.clear();
  events.reserve(fd_map_.size());

#if SOCKETWIRE_PLATFORM_WINDOWS
  if (backend_ == PollBackend::kWsaPoll) {
    if (poll_fds_.empty()) return;

    const int wait_time = (timeout_ms < 0) ? -1 : timeout_ms;
    const int n = ::WSAPoll(poll_fds_.data(),
                            static_cast<ULONG>(poll_fds_.size()), wait_time);

    if (n > 0) {
      for (const auto& pfd : poll_fds_) {
        if (pfd.revents == 0) continue;

        int fd = static_cast<int>(pfd.fd);
        auto it = fd_map_.find(fd);
        if (it == fd_map_.end()) continue;

        bool r = (pfd.revents & POLLIN) != 0;
        bool w = (pfd.revents & POLLOUT) != 0;
        bool e = (pfd.revents & POLLERR) != 0;
        bool c = (pfd.revents & POLLHUP) != 0;
        events.push_back(MakeEvent(it->second.socket, r, w, e, c));
      }
    }
    return;
  }
  return;
#else

#if SOCKETWIRE_PLATFORM_LINUX
  if (backend_ == PollBackend::kEpoll) {
    constexpr int kMaxEvents = 64;
    epoll_event evs[kMaxEvents];
    const int wait_time = (timeout_ms < 0) ? -1 : timeout_ms;
    const int n = ::epoll_wait(epoll_fd_, evs, kMaxEvents, wait_time);
    for (int i = 0; i < n; ++i) {
      int fd = evs[i].data.fd;
      auto it = fd_map_.find(fd);
      if (it == fd_map_.end()) continue;
      bool r = (evs[i].events & EPOLLIN) != 0;
      bool w = (evs[i].events & EPOLLOUT) != 0;
      bool e = (evs[i].events & (EPOLLERR | EPOLLHUP)) != 0;
      bool c = (evs[i].events & EPOLLHUP) != 0;
      events.push_back(MakeEvent(it->second.socket, r, w, e, c));
    }
    return;
  }
#endif

#if SOCKETWIRE_PLATFORM_APPLE
  if (backend_ == PollBackend::kKqueue) {
    constexpr int max_events = 64;
    struct kevent kev[max_events];
    struct timespec ts{};
    const struct timespec* pts = nullptr;
    if (timeout_ms >= 0) {
      ts.tv_sec = timeout_ms / 1000;
      ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
      pts = &ts;
    }
    const int n = ::kevent(kqueue_fd_, nullptr, 0, kev, max_events, pts);

    for (int i = 0; i < n; ++i) {
      const int fd = static_cast<int>(kev[i].ident);
      auto it = fd_map_.find(fd);
      if (it == fd_map_.end()) continue;

      SocketEvent* event = nullptr;
      for (auto& candidate : events) {
        if (candidate.socket == it->second.socket) {
          event = &candidate;
          break;
        }
      }
      if (event == nullptr) {
        events.push_back(MakeEvent(it->second.socket, false, false, false,
                                   false));
        event = &events.back();
      }

      if (kev[i].filter == EVFILT_READ) event->readable = true;
      if (kev[i].filter == EVFILT_WRITE) event->writable = true;
      if ((kev[i].flags & EV_ERROR) != 0) event->error = true;
      if ((kev[i].flags & EV_EOF) != 0) event->closed = true;
    }
    return;
  }
#endif

  if (backend_ == PollBackend::kSelect) {
    fd_set r_set = read_set_;
    fd_set w_set = write_set_;
    fd_set e_set = error_set_;
    struct timeval tv{};
    struct timeval* ptv = nullptr;
    if (timeout_ms >= 0) {
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;
      ptv = &tv;
    }
    const int n = ::select(select_max_fd_ + 1, &r_set, &w_set, &e_set, ptv);
    if (n > 0) {
      for (auto& kv : fd_map_) {
        const int fd = kv.first;
        const bool r = FD_ISSET(fd, &r_set) != 0;
        const bool w = FD_ISSET(fd, &w_set) != 0;
        const bool e = FD_ISSET(fd, &e_set) != 0;
        if (!r && !w && !e) continue;
        events.push_back(MakeEvent(kv.second.socket, r, w, e, false));
      }
    }
  }

  return;
#endif
}

PollBackend SocketPoller::BackendType() const { return backend_; }

}  // namespace socketwire
