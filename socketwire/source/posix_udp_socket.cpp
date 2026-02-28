#include "i_socket.hpp"

#include <cstring>
#include <cerrno>
#include <cassert>

#if defined(_WIN32) || defined(_WIN64)
  #error "posix_udp_socket.cpp is for POSIX platforms only (Linux/macOS/BSD)."
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

#include "socket_address_utils.hpp"

namespace socketwire
{

// Pull shared address-conversion helpers into this TU's namespace.
using detail::is_ipv4_mapped;
using detail::socketaddress_from_sockaddr;
using detail::fill_sockaddr_storage;

// ERRORS MAP errno -> SocketError
static SocketError map_errno(int e)
{
  switch (e)
  {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return SocketError::WouldBlock;
    case EBADF:
    case ENOTSOCK:
    case EINVAL:
      return SocketError::InvalidParam;
    case ECONNRESET:
    case ENOTCONN:
    case EPIPE:
      return SocketError::Closed;
    default:
      return SocketError::System;
  }
}


// POSIX UDP implementation based on ISocket.
class PosixUDPSocket final : public ISocket
{
public:
  explicit PosixUDPSocket(const SocketConfig& cfg);
  ~PosixUDPSocket() override;

  SocketError bind(const SocketAddress& address, std::uint16_t port) override;
  SocketResult sendTo(const void* data,
                      std::size_t length,
                      const SocketAddress& toAddr,
                      std::uint16_t toPort) override;
  SocketResult receive(void* buffer,
                       std::size_t capacity,
                       SocketAddress& fromAddr,
                       std::uint16_t& fromPort) override;
  void poll(ISocketEventHandler* handler) override;
  SocketError setBlocking(bool enable) override;
  bool isBlocking() const override;
  std::uint16_t localPort() const override;
  SocketType type() const override;
  int nativeHandle() const override;
  void close() override;

private:
  int fd = -1;
  bool blocking = false;
  std::uint16_t boundPort = 0;
  SocketConfig config;
  int family = AF_UNSPEC;
};

PosixUDPSocket::PosixUDPSocket(const SocketConfig& cfg)
  : config(cfg)
{
}

PosixUDPSocket::~PosixUDPSocket()
{
  close();
}

SocketError PosixUDPSocket::bind(const SocketAddress& address, std::uint16_t port)
{
  if (fd != -1)
    return SocketError::InvalidParam; // already open

  if (address.isIPv6 && !config.enableIPv6)
    return SocketError::Unsupported;

  family = address.isIPv6 ? AF_INET6 : AF_INET;
  fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == -1)
    return map_errno(errno);

  if (family == AF_INET6)
  {
    int v6only = config.enableIPv6 ? 0 : 1; // 0 allows dual-stack
    ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
  }

  if (config.reuseAddress)
  {
    int v = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
  }
  if (config.sendBufferSize > 0)
    ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &config.sendBufferSize, sizeof(int));
  if (config.recvBufferSize > 0)
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &config.recvBufferSize, sizeof(int));

  if (config.nonBlocking)
  {
    ::fcntl(fd, F_SETFL, O_NONBLOCK);
    blocking = false;
  }

  sockaddr_storage addr{};
  socklen_t addrLen = 0;
  int targetFamily = AF_UNSPEC;
  if (!fill_sockaddr_storage(address, port, family == AF_INET6, addr, targetFamily, addrLen))
  {
    ::close(fd);
    fd = -1;
    family = AF_UNSPEC;
    return SocketError::InvalidParam;
  }

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), addrLen) != 0)
  {
    SocketError err = map_errno(errno);
    ::close(fd);
    fd = -1;
    family = AF_UNSPEC;
    return err;
  }

  // Get the actual assigned port (important when port == 0)
  sockaddr_storage boundAddr{};
  socklen_t boundLen = sizeof(boundAddr);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen) == 0)
  {
    if (boundAddr.ss_family == AF_INET)
    {
      boundPort = ntohs(reinterpret_cast<sockaddr_in*>(&boundAddr)->sin_port);
    }
    else if (boundAddr.ss_family == AF_INET6)
    {
      boundPort = ntohs(reinterpret_cast<sockaddr_in6*>(&boundAddr)->sin6_port);
    }
  }
  else
  {
    boundPort = port; // fallback
  }

  return SocketError::None;
}

SocketResult PosixUDPSocket::sendTo(const void* data,
                                    std::size_t length,
                                    const SocketAddress& toAddr,
                                    std::uint16_t toPort)
{
  if (data == nullptr || length == 0)
    return { -1, SocketError::InvalidParam };

  if (fd != -1 && toAddr.isIPv6 && family == AF_INET)
    return { -1, SocketError::Unsupported };

  if (toAddr.isIPv6 && !config.enableIPv6)
    return { -1, SocketError::Unsupported };

  // Lazy open if socket is not created (could require bind — but UDP allows send without bind).
  if (fd == -1)
  {
    family = toAddr.isIPv6 ? AF_INET6 : AF_INET;
    fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1)
      return { -1, map_errno(errno) };

    if (family == AF_INET6)
    {
      int v6only = config.enableIPv6 ? 0 : 1;
      ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    if (config.nonBlocking)
    {
      ::fcntl(fd, F_SETFL, O_NONBLOCK);
      blocking = false;
    }
    // reuseAddress for sender — optional
    if (config.reuseAddress)
    {
      int v = 1;
      ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
    }
  }

  sockaddr_storage addr{};
  socklen_t addrLen = 0;
  int targetFamily = AF_UNSPEC;
  if (!fill_sockaddr_storage(toAddr, toPort, family == AF_INET6, addr, targetFamily, addrLen))
    return { -1, SocketError::InvalidParam };

  ssize_t sent = ::sendto(fd,
                          reinterpret_cast<const char*>(data),
                          length,
                          0,
                          reinterpret_cast<sockaddr*>(&addr),
                          addrLen);
  if (sent == -1)
    return { -1, map_errno(errno) };

  return { sent, SocketError::None };
}

SocketResult PosixUDPSocket::receive(void* buffer,
                                     std::size_t capacity,
                                     SocketAddress& fromAddr,
                                     std::uint16_t& fromPort)
{
  if (fd == -1)
    return { -1, SocketError::NotBound };
  if (buffer == nullptr || capacity == 0)
    return { -1, SocketError::InvalidParam };

  sockaddr_storage addr{};
  socklen_t len = sizeof(addr);
  ssize_t got = ::recvfrom(fd,
                           reinterpret_cast<char*>(buffer),
                           capacity,
                           0,
                           reinterpret_cast<sockaddr*>(&addr),
                           &len);
  if (got == -1)
    return { -1, map_errno(errno) };

  fromAddr = socketaddress_from_sockaddr(addr);
  if (addr.ss_family == AF_INET)
    fromPort = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
  else if (addr.ss_family == AF_INET6)
    fromPort = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
  else
    fromPort = 0;
  return { got, SocketError::None };
}

void PosixUDPSocket::poll(ISocketEventHandler* handler)
{
  if (handler == nullptr || fd == -1)
    return;

  // Single read loop until WouldBlock.
  for (;;)
  {
    SocketAddress from;
    std::uint16_t port = 0;
    char temp[2048];
    SocketResult r = receive(temp, sizeof(temp), from, port);
    if (!r.succeeded())
    {
      if (r.error != SocketError::WouldBlock)
        handler->onSocketError(r.error);
      break;
    }
    if (r.bytes <= 0)
      break;
    handler->onDataReceived(from, port, temp, static_cast<std::size_t>(r.bytes));

    // Heuristic: if received less than full buffer — finish
    if (r.bytes < static_cast<std::ptrdiff_t>(sizeof(temp)))
      break;
  }
}

SocketError PosixUDPSocket::setBlocking(bool enable)
{
  if (fd == -1)
    return SocketError::NotBound;

  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return map_errno(errno);

  if (enable)
    flags &= ~O_NONBLOCK;
  else
    flags |= O_NONBLOCK;

  if (::fcntl(fd, F_SETFL, flags) == -1)
    return map_errno(errno);

  blocking = enable;
  return SocketError::None;
}

bool PosixUDPSocket::isBlocking() const
{
  return blocking;
}

std::uint16_t PosixUDPSocket::localPort() const
{
  return boundPort;
}

SocketType PosixUDPSocket::type() const
{
  return SocketType::UDP;
}

int PosixUDPSocket::nativeHandle() const
{
  return fd;
}

void PosixUDPSocket::close()
{
  if (fd != -1)
  {
    ::close(fd);
    fd = -1;
    boundPort = 0;
    family = AF_UNSPEC;
  }
}


// POSIX Socket Factory (currently implements only UDP).
class PosixSocketFactory : public ISocketFactory
{
public:
  std::unique_ptr<ISocket> createSocket(SocketType type,
                                        const SocketConfig& cfg) override
  {
    switch (type)
    {
      case SocketType::UDP:
        return std::make_unique<PosixUDPSocket>(cfg);
      case SocketType::TCP:
        // TODO: add TCP socket implementation (PosixTCPSocket)
        return nullptr;
      default:
        return nullptr;
    }
  }
};


// Public function to register the factory. Call once during network layer initialization.
void register_posix_socket_factory()
{
  static PosixSocketFactory factory;
  SocketFactoryRegistry::setFactory(&factory);
}

} // namespace socketwire
