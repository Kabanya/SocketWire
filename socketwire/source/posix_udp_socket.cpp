#include <algorithm>
#include <array>
#include <cerrno>
#include <utility>

#include "i_socket.hpp"

#if defined(_WIN32) || defined(_WIN64)
#error "posix_udp_socket.cpp is for POSIX platforms only (Linux/macOS/BSD)."
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket_address_utils.hpp"

namespace socketwire {

// ERRORS MAP errno -> SocketError
static SocketError MapErrno(int e) {
  switch (e) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return SocketError::kWouldBlock;
    case EBADF:
    case ENOTSOCK:
    case EINVAL:
      return SocketError::kInvalidParam;
    case ECONNRESET:
    case ENOTCONN:
    case EPIPE:
      return SocketError::kClosed;
    default:
      return SocketError::kSystem;
  }
}

// POSIX UDP implementation based on ISocket.
class PosixUDPSocket final : public ISocket {
 public:
  explicit PosixUDPSocket(const SocketConfig& cfg);
  ~PosixUDPSocket() override;

  SocketError Bind(const SocketAddress& address, std::uint16_t port) override;
  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override;
  std::size_t SendMany(std::span<const OutgoingDatagram> datagrams) override;
  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override;
  std::size_t ReceiveMany(std::span<IncomingDatagram> datagrams) override;
  void Poll(ISocketEventHandler* handler) override;
  SocketError SetBlocking(bool enable) override;
  [[nodiscard]] bool IsBlocking() const override;
  [[nodiscard]] std::uint16_t LocalPort() const override;
  [[nodiscard]] int NativeHandle() const override;
  void Close() override;

 private:
  int fd_ = -1;
  bool blocking_ = false;
  std::uint16_t bound_port_ = 0;
  SocketConfig config_;
  int family_ = AF_UNSPEC;
};

PosixUDPSocket::PosixUDPSocket(const SocketConfig& cfg) : config_(cfg) {}

PosixUDPSocket::~PosixUDPSocket() { Close(); }

SocketError PosixUDPSocket::Bind(const SocketAddress& address,
                                 std::uint16_t port) {
  if (fd_ != -1) return SocketError::kInvalidParam;  // already open

  if (address.isIPv6 && !config_.enableIPv6) return SocketError::kUnsupported;

  family_ = address.isIPv6 ? AF_INET6 : AF_INET;
  fd_ = ::socket(family_, SOCK_DGRAM, IPPROTO_UDP);
  if (fd_ == -1) return MapErrno(errno);

  if (family_ == AF_INET6) {
    int v6only = config_.enableIPv6 ? 0 : 1;  // 0 allows dual-stack
    ::setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
  }

  if (config_.reuseAddress) {
    int v = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
  }
  if (config_.sendBufferSize > 0) {
    ::setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &config_.sendBufferSize,
                 sizeof(int));
  }
  if (config_.recvBufferSize > 0) {
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &config_.recvBufferSize,
                 sizeof(int));
  }

  if (config_.nonBlocking) {
    ::fcntl(fd_, F_SETFL, O_NONBLOCK);
    blocking_ = false;
  }

  sockaddr_storage addr{};
  socklen_t addr_len = 0;
  int target_family = AF_UNSPEC;
  if (!detail::FillSockaddrStorage(address, port, family_ == AF_INET6, addr,
                                   target_family, addr_len)) {
    ::close(fd_);
    fd_ = -1;
    family_ = AF_UNSPEC;
    return SocketError::kInvalidParam;
  }

  if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
    const SocketError err = MapErrno(errno);
    ::close(fd_);
    fd_ = -1;
    family_ = AF_UNSPEC;
    return err;
  }

  // Get the actual assigned port (important when port == 0)
  sockaddr_storage bound_addr{};
  socklen_t bound_len = sizeof(bound_addr);
  if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&bound_addr),
                    &bound_len) == 0) {
    if (bound_addr.ss_family == AF_INET) {
      bound_port_ =
          ntohs(reinterpret_cast<sockaddr_in*>(&bound_addr)->sin_port);
    } else if (bound_addr.ss_family == AF_INET6) {
      bound_port_ =
          ntohs(reinterpret_cast<sockaddr_in6*>(&bound_addr)->sin6_port);
    }
  } else {
    bound_port_ = port;  // fallback
  }

  return SocketError::kNone;
}

SocketResult PosixUDPSocket::SendTo(const void* data, std::size_t length,
                                    const SocketAddress& to_addr,
                                    std::uint16_t to_port) {
  if (data == nullptr || length == 0) {
    return {.bytes = -1, .error = SocketError::kInvalidParam};
  }

  if (fd_ != -1 && to_addr.isIPv6 && family_ == AF_INET) {
    return {.bytes = -1, .error = SocketError::kUnsupported};
  }

  if (to_addr.isIPv6 && !config_.enableIPv6) {
    return {.bytes = -1, .error = SocketError::kUnsupported};
  }

  // Open lazily because UDP sockets can send without an explicit bind().
  if (fd_ == -1) {
    family_ = to_addr.isIPv6 ? AF_INET6 : AF_INET;
    fd_ = ::socket(family_, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ == -1) return {.bytes = -1, .error = MapErrno(errno)};

    if (family_ == AF_INET6) {
      int v6only = config_.enableIPv6 ? 0 : 1;
      ::setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    if (config_.nonBlocking) {
      ::fcntl(fd_, F_SETFL, O_NONBLOCK);
      blocking_ = false;
    }
    if (config_.reuseAddress) {
      int v = 1;
      ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
    }
  }

  sockaddr_storage addr{};
  socklen_t addr_len = 0;
  int target_family = AF_UNSPEC;
  if (!detail::FillSockaddrStorage(to_addr, to_port, family_ == AF_INET6, addr,
                                   target_family, addr_len)) {
    return {.bytes = -1, .error = SocketError::kInvalidParam};
  }

  const ssize_t sent =
      ::sendto(fd_, reinterpret_cast<const char*>(data), length, 0,
               reinterpret_cast<sockaddr*>(&addr), addr_len);
  if (std::cmp_equal(sent, -1)) return {.bytes = -1, .error = MapErrno(errno)};

  return {.bytes = static_cast<ptrdiff_t>(sent), .error = SocketError::kNone};
}

std::size_t PosixUDPSocket::SendMany(
    std::span<const OutgoingDatagram> datagrams) {
#if defined(__linux__)
  if (datagrams.empty()) return 0;

  std::size_t sent_count = 0;
  if (fd_ == -1) {
    const auto& first = datagrams.front();
    const SocketResult first_result =
        SendTo(first.data, first.size, first.toAddr, first.toPort);
    if (first_result.Failed()) return 0;
    sent_count = 1;
    datagrams = datagrams.subspan(1);
    if (datagrams.empty()) return sent_count;
  }

  static constexpr std::size_t kMaxBatch = 64;
  while (!datagrams.empty()) {
    const std::size_t count = std::min(kMaxBatch, datagrams.size());
    std::array<mmsghdr, kMaxBatch> messages{};
    std::array<iovec, kMaxBatch> iovecs{};
    std::array<sockaddr_storage, kMaxBatch> addresses{};
    std::array<socklen_t, kMaxBatch> address_lengths{};

    std::size_t prepared = 0;
    for (; prepared < count; ++prepared) {
      const auto& datagram = datagrams[prepared];
      if (datagram.data == nullptr || datagram.size == 0) break;
      if (fd_ != -1 && datagram.toAddr.isIPv6 && family_ == AF_INET) break;
      if (datagram.toAddr.isIPv6 && !config_.enableIPv6) break;

      int target_family = AF_UNSPEC;
      if (!detail::FillSockaddrStorage(
              datagram.toAddr, datagram.toPort, family_ == AF_INET6,
              addresses[prepared], target_family, address_lengths[prepared])) {
        break;
      }

      iovecs[prepared].iov_base = const_cast<void*>(datagram.data);
      iovecs[prepared].iov_len = datagram.size;
      messages[prepared].msg_hdr.msg_iov = &iovecs[prepared];
      messages[prepared].msg_hdr.msg_iovlen = 1;
      messages[prepared].msg_hdr.msg_name = &addresses[prepared];
      messages[prepared].msg_hdr.msg_namelen = address_lengths[prepared];
    }

    if (prepared == 0) break;

    const int sent = ::sendmmsg(fd_, messages.data(),
                                static_cast<unsigned int>(prepared), 0);
    if (sent == -1) break;

    sent_count += static_cast<std::size_t>(sent);
    datagrams = datagrams.subspan(static_cast<std::size_t>(sent));
    if (static_cast<std::size_t>(sent) < prepared) break;
  }

  return sent_count;
#else
  return ISocket::SendMany(datagrams);
#endif
}

SocketResult PosixUDPSocket::Receive(void* buffer, std::size_t capacity,
                                     SocketAddress& from_addr,
                                     std::uint16_t& from_port) {
  if (fd_ == -1) return {.bytes = -1, .error = SocketError::kNotBound};
  if (buffer == nullptr || capacity == 0) {
    return {.bytes = -1, .error = SocketError::kInvalidParam};
  }

  sockaddr_storage addr{};
  socklen_t len = sizeof(addr);
  const ssize_t got = ::recvfrom(fd_, reinterpret_cast<char*>(buffer), capacity,
                                 0, reinterpret_cast<sockaddr*>(&addr), &len);
  if (std::cmp_equal(got, -1)) return {.bytes = -1, .error = MapErrno(errno)};

  from_addr = detail::SocketAddressFromSockaddr(addr);
  if (addr.ss_family == AF_INET) {
    from_port = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    from_port = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
  } else {
    from_port = 0;
  }
  return {.bytes = got, .error = SocketError::kNone};
}

std::size_t PosixUDPSocket::ReceiveMany(std::span<IncomingDatagram> datagrams) {
#if defined(__linux__)
  if (fd_ == -1 || datagrams.empty()) return 0;

  static constexpr std::size_t kMaxBatch = 64;
  const std::size_t count = std::min(kMaxBatch, datagrams.size());
  std::array<mmsghdr, kMaxBatch> messages{};
  std::array<iovec, kMaxBatch> iovecs{};
  std::array<sockaddr_storage, kMaxBatch> addresses{};

  std::size_t prepared = 0;
  for (; prepared < count; ++prepared) {
    auto& datagram = datagrams[prepared];
    if (datagram.data == nullptr || datagram.capacity == 0) break;
    iovecs[prepared].iov_base = datagram.data;
    iovecs[prepared].iov_len = datagram.capacity;
    messages[prepared].msg_hdr.msg_iov = &iovecs[prepared];
    messages[prepared].msg_hdr.msg_iovlen = 1;
    messages[prepared].msg_hdr.msg_name = &addresses[prepared];
    messages[prepared].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
  }

  if (prepared == 0) return 0;

  const int received = ::recvmmsg(
      fd_, messages.data(), static_cast<unsigned int>(prepared), 0, nullptr);
  if (received == -1) return 0;

  for (int i = 0; i < received; ++i) {
    auto& datagram = datagrams[static_cast<std::size_t>(i)];
    const auto& addr = addresses[static_cast<std::size_t>(i)];
    datagram.fromAddr = detail::SocketAddressFromSockaddr(addr);
    if (addr.ss_family == AF_INET) {
      datagram.fromPort =
          ntohs(reinterpret_cast<const sockaddr_in*>(&addr)->sin_port);
    } else if (addr.ss_family == AF_INET6) {
      datagram.fromPort =
          ntohs(reinterpret_cast<const sockaddr_in6*>(&addr)->sin6_port);
    } else {
      datagram.fromPort = 0;
    }
    datagram.result = {.bytes = static_cast<std::ptrdiff_t>(
                           messages[static_cast<std::size_t>(i)].msg_len),
                       .error = SocketError::kNone};
  }

  return static_cast<std::size_t>(received);
#else
  return ISocket::ReceiveMany(datagrams);
#endif
}

void PosixUDPSocket::Poll(ISocketEventHandler* handler) {
  if (handler == nullptr || fd_ == -1) return;

  // Single read loop until WouldBlock.
  for (;;) {
    SocketAddress from;
    std::uint16_t port = 0;
    char temp[2048];
    const SocketResult r = Receive(temp, sizeof(temp), from, port);
    if (!r.Succeeded()) {
      if (r.error != SocketError::kWouldBlock) handler->OnSocketError(r.error);
      break;
    }
    if (r.bytes <= 0) break;
    handler->OnDataReceived(from, port, temp,
                            static_cast<std::size_t>(r.bytes));

    // A short read means the socket buffer is likely drained.
    if (std::cmp_less(r.bytes, sizeof(temp))) break;
  }
}

SocketError PosixUDPSocket::SetBlocking(bool enable) {
  if (fd_ == -1) return SocketError::kNotBound;

  int flags = ::fcntl(fd_, F_GETFL, 0);
  if (flags == -1) return MapErrno(errno);

  if (enable) {
    flags &= ~O_NONBLOCK;
  } else {
    flags |= O_NONBLOCK;
  }

  if (::fcntl(fd_, F_SETFL, flags) == -1) return MapErrno(errno);

  blocking_ = enable;
  return SocketError::kNone;
}

bool PosixUDPSocket::IsBlocking() const { return blocking_; }

std::uint16_t PosixUDPSocket::LocalPort() const { return bound_port_; }

int PosixUDPSocket::NativeHandle() const { return fd_; }

void PosixUDPSocket::Close() {
  if (fd_ != -1) {
    ::close(fd_);
    fd_ = -1;
    bound_port_ = 0;
    family_ = AF_UNSPEC;
  }
}

class PosixSocketFactory : public ISocketFactory {
 public:
  std::unique_ptr<ISocket> CreateUdpSocket(const SocketConfig& cfg) override {
    return std::make_unique<PosixUDPSocket>(cfg);
  }
};

// Public function to register the factory. Call once during network layer
// initialization.
void RegisterPosixSocketFactory() {
  static PosixSocketFactory factory;
  SocketFactoryRegistry::SetFactory(&factory);
}

}  // namespace socketwire
