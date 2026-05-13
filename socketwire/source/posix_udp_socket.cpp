#include <cassert>
#include <cerrno>
#include <cstring>
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

// Pull shared address-conversion helpers into this TU's namespace.
using detail::FillSockaddrStorage;
using detail::SocketaddressFromSockaddr;

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
  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override;
  void Poll(ISocketEventHandler* handler) override;
  SocketError SetBlocking(bool enable) override;
  [[nodiscard]] bool IsBlocking() const override;
  [[nodiscard]] std::uint16_t LocalPort() const override;
  [[nodiscard]] SocketType Type() const override;
  [[nodiscard]] int NativeHandle() const override;
  void Close() override;

 private:
  int fd = -1;
  bool blocking = false;
  std::uint16_t bound_port = 0;
  SocketConfig config;
  int family = AF_UNSPEC;
};

PosixUDPSocket::PosixUDPSocket(const SocketConfig& cfg) : config(cfg) {}

PosixUDPSocket::~PosixUDPSocket() { Close(); }

SocketError PosixUDPSocket::Bind(const SocketAddress& address,
                                 std::uint16_t port) {
  if (fd != -1) return SocketError::kInvalidParam;  // already open

  if (address.isIPv6 && !config.enableIPv6) return SocketError::kUnsupported;

  family = address.isIPv6 ? AF_INET6 : AF_INET;
  fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == -1) return MapErrno(errno);

  if (family == AF_INET6) {
    int v6only = config.enableIPv6 ? 0 : 1;  // 0 allows dual-stack
    ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
  }

  if (config.reuseAddress) {
    int v = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
  }
  if (config.sendBufferSize > 0) {
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &config.sendBufferSize,
                 sizeof(int));
  }
  if (config.recvBufferSize > 0) {
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &config.recvBufferSize,
                 sizeof(int));
  }

  if (config.nonBlocking) {
    ::fcntl(fd, F_SETFL, O_NONBLOCK);
    blocking = false;
  }

  sockaddr_storage addr{};
  socklen_t addr_len = 0;
  int target_family = AF_UNSPEC;
  if (!FillSockaddrStorage(address, port, family == AF_INET6, addr,
                           target_family, addr_len)) {
    ::close(fd);
    fd = -1;
    family = AF_UNSPEC;
    return SocketError::kInvalidParam;
  }

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
    const SocketError err = MapErrno(errno);
    ::close(fd);
    fd = -1;
    family = AF_UNSPEC;
    return err;
  }

  // Get the actual assigned port (important when port == 0)
  sockaddr_storage bound_addr{};
  socklen_t bound_len = sizeof(bound_addr);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound_addr), &bound_len) ==
      0) {
    if (bound_addr.ss_family == AF_INET) {
      bound_port = ntohs(reinterpret_cast<sockaddr_in*>(&bound_addr)->sin_port);
    } else if (bound_addr.ss_family == AF_INET6) {
      bound_port =
          ntohs(reinterpret_cast<sockaddr_in6*>(&bound_addr)->sin6_port);
    }
  } else {
    bound_port = port;  // fallback
  }

  return SocketError::kNone;
}

SocketResult PosixUDPSocket::SendTo(const void* data, std::size_t length,
                                    const SocketAddress& to_addr,
                                    std::uint16_t to_port) {
  if (data == nullptr || length == 0) {
    return {.bytes = -1, .error = SocketError::kInvalidParam};
  }

  if (fd != -1 && to_addr.isIPv6 && family == AF_INET) {
    return {.bytes = -1, .error = SocketError::kUnsupported};
  }

  if (to_addr.isIPv6 && !config.enableIPv6) {
    return {.bytes = -1, .error = SocketError::kUnsupported};
  }

  // Lazy open if socket is not created (could require bind — but UDP allows
  // send without bind).
  if (fd == -1) {
    family = to_addr.isIPv6 ? AF_INET6 : AF_INET;
    fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) return {.bytes = -1, .error = MapErrno(errno)};

    if (family == AF_INET6) {
      int v6only = config.enableIPv6 ? 0 : 1;
      ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    if (config.nonBlocking) {
      ::fcntl(fd, F_SETFL, O_NONBLOCK);
      blocking = false;
    }
    // reuseAddress for sender — optional
    if (config.reuseAddress) {
      int v = 1;
      ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
    }
  }

  sockaddr_storage addr{};
  socklen_t addr_len = 0;
  int target_family = AF_UNSPEC;
  if (!FillSockaddrStorage(to_addr, to_port, family == AF_INET6, addr,
                           target_family, addr_len)) {
    return {.bytes = -1, .error = SocketError::kInvalidParam};
  }

  const ssize_t sent = ::sendto(fd, reinterpret_cast<const char*>(data), length, 0,
                      reinterpret_cast<sockaddr*>(&addr), addr_len);
  if (std::cmp_equal(sent , -1)) return {.bytes = -1, .error = MapErrno(errno)};

  return {.bytes = static_cast<ptrdiff_t>(sent), .error = SocketError::kNone};
}

SocketResult PosixUDPSocket::Receive(void* buffer, std::size_t capacity,
                                     SocketAddress& from_addr,
                                     std::uint16_t& from_port) {
  if (fd == -1) return {.bytes = -1, .error = SocketError::kNotBound};
  if (buffer == nullptr || capacity == 0) {
    return {.bytes = -1, .error = SocketError::kInvalidParam};
  }

  sockaddr_storage addr{};
  socklen_t len = sizeof(addr);
  const ssize_t got = ::recvfrom(fd, reinterpret_cast<char*>(buffer), capacity, 0,
                           reinterpret_cast<sockaddr*>(&addr), &len);
  if (std::cmp_equal(got, -1)) return {.bytes = -1, .error = MapErrno(errno)};

  from_addr = SocketaddressFromSockaddr(addr);
  if (addr.ss_family == AF_INET) {
    from_port = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
  } else if (addr.ss_family == AF_INET6) {
    from_port = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
  } else {
    from_port = 0;
  }
  return {.bytes = got, .error = SocketError::kNone};
}

void PosixUDPSocket::Poll(ISocketEventHandler* handler) {
  if (handler == nullptr || fd == -1) return;

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

    // Heuristic: if received less than full buffer — finish
    if (std::cmp_less(r.bytes, sizeof(temp))) break;
  }
}

SocketError PosixUDPSocket::SetBlocking(bool enable) {
  if (fd == -1) return SocketError::kNotBound;

  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags == -1) return MapErrno(errno);

  if (enable) {
    flags &= ~O_NONBLOCK;
  } else {
    flags |= O_NONBLOCK;
  }

  if (::fcntl(fd, F_SETFL, flags) == -1) return MapErrno(errno);

  blocking = enable;
  return SocketError::kNone;
}

bool PosixUDPSocket::IsBlocking() const { return blocking; }

std::uint16_t PosixUDPSocket::LocalPort() const { return bound_port; }

SocketType PosixUDPSocket::Type() const { return SocketType::kUdp; }

int PosixUDPSocket::NativeHandle() const { return fd; }

void PosixUDPSocket::Close() {
  if (fd != -1) {
    ::close(fd);
    fd = -1;
    bound_port = 0;
    family = AF_UNSPEC;
  }
}

// POSIX Socket Factory (currently implements only UDP).
class PosixSocketFactory : public ISocketFactory {
 public:
  std::unique_ptr<ISocket> CreateSocket(SocketType type,
                                        const SocketConfig& cfg) override {
    switch (type) {
      case SocketType::kUdp:
        return std::make_unique<PosixUDPSocket>(cfg);
      case SocketType::kTcp:
      default:
        return nullptr;
    }
  }
};

// Public function to register the factory. Call once during network layer
// initialization.
void RegisterPosixSocketFactory() {
  static PosixSocketFactory factory;
  SocketFactoryRegistry::SetFactory(&factory);
}

}  // namespace socketwire
