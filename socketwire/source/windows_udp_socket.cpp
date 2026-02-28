#include "i_socket.hpp"

#include <cstring>
#include <cassert>

#ifdef __clangd__
namespace socketwire
{
void register_windows_socket_factory() {}
} // namespace socketwire
#else

#if !defined(_WIN32) && !defined(_WIN64)
  #error "windows_udp_socket.cpp is for Windows platforms only."
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "socket_address_utils.hpp"

// Link with Winsock library (MSVC only, GCC uses CMake target_link_libraries)
#ifdef _MSC_VER
  #pragma comment(lib, "ws2_32.lib")
#endif

namespace socketwire
{

// Pull shared address-conversion helpers into this TU's namespace.
using detail::is_ipv4_mapped;
using detail::socketaddress_from_sockaddr;
using detail::fill_sockaddr_storage;

// Global WSA initialization helper
class WSAInitializer
{
public:
  WSAInitializer()
  {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    initialized = (result == 0);
  }

  ~WSAInitializer()
  {
    if (initialized)
    {
      WSACleanup();
    }
  }

  bool isInitialized() const { return initialized; }

private:
  bool initialized = false;
};

static WSAInitializer& getWSAInitializer()
{
  static WSAInitializer instance;
  return instance;
}

// Error mapping WSAGetLastError -> SocketError
static SocketError map_wsa_error(int wsaError)
{
  switch (wsaError)
  {
    case WSAEWOULDBLOCK:
      return SocketError::WouldBlock;
    case WSAEBADF:
    case WSAENOTSOCK:
    case WSAEINVAL:
      return SocketError::InvalidParam;
    case WSAECONNRESET:
    case WSAENOTCONN:
    case WSAENETRESET:
    case WSAECONNABORTED:
      return SocketError::Closed;
    case WSAENETDOWN:
    case WSAENETUNREACH:
    case WSAEHOSTDOWN:
    case WSAEHOSTUNREACH:
      return SocketError::System;
    default:
      return SocketError::System;
  }
}

static SocketError map_last_error()
{
  return map_wsa_error(WSAGetLastError());
}

// Windows UDP implementation based on ISocket
class WindowsUDPSocket final : public ISocket
{
public:
  explicit WindowsUDPSocket(const SocketConfig& cfg);
  ~WindowsUDPSocket() override;

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
  SOCKET sock = INVALID_SOCKET;
  bool blocking = false;
  std::uint16_t boundPort = 0;
  SocketConfig config;
  int family = AF_UNSPEC;
};

WindowsUDPSocket::WindowsUDPSocket(const SocketConfig& cfg)
  : config(cfg)
{
  // Ensure WSA is initialized
  getWSAInitializer();
}

WindowsUDPSocket::~WindowsUDPSocket()
{
  close();
}

SocketError WindowsUDPSocket::bind(const SocketAddress& address, std::uint16_t port)
{
  if (!getWSAInitializer().isInitialized())
    return SocketError::System;

  if (address.isIPv6 && !config.enableIPv6)
    return SocketError::Unsupported;

  if (sock != INVALID_SOCKET)
    return SocketError::InvalidParam; // already open

  family = address.isIPv6 ? AF_INET6 : AF_INET;
  sock = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET)
    return map_last_error();

  if (family == AF_INET6)
  {
    // Enable dual-stack if requested so IPv4-mapped addresses are accepted
    BOOL v6only = config.enableIPv6 ? FALSE : TRUE;
    ::setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
                 reinterpret_cast<const char*>(&v6only), sizeof(v6only));
  }

  if (config.reuseAddress)
  {
    BOOL v = TRUE;
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&v), sizeof(v));
  }
  if (config.sendBufferSize > 0)
  {
    int size = config.sendBufferSize;
    ::setsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&size), sizeof(size));
  }
  if (config.recvBufferSize > 0)
  {
    int size = config.recvBufferSize;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&size), sizeof(size));
  }

  if (config.nonBlocking)
  {
    u_long mode = 1;
    ::ioctlsocket(sock, FIONBIO, &mode);
    blocking = false;
  }
  else
  {
    blocking = true;
  }

  sockaddr_storage addr{};
  int addrLen = 0;
  int targetFamily = AF_UNSPEC;
  if (!fill_sockaddr_storage(address, port, family == AF_INET6, addr, targetFamily, addrLen))
  {
    ::closesocket(sock);
    sock = INVALID_SOCKET;
    family = AF_UNSPEC;
    return SocketError::InvalidParam;
  }

  if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), addrLen) != 0)
  {
    SocketError err = map_last_error();
    ::closesocket(sock);
    sock = INVALID_SOCKET;
    family = AF_UNSPEC;
    return err;
  }

  // Get the actual assigned port (important when port == 0)
  sockaddr_storage boundAddr{};
  int boundLen = sizeof(boundAddr);
  if (::getsockname(sock, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen) == 0)
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

SocketResult WindowsUDPSocket::sendTo(const void* data,
                                      std::size_t length,
                                      const SocketAddress& toAddr,
                                      std::uint16_t toPort)
{
  if (!getWSAInitializer().isInitialized())
    return { -1, SocketError::System };

  if (data == nullptr || length == 0)
    return { -1, SocketError::InvalidParam };

  if (sock != INVALID_SOCKET && toAddr.isIPv6 && family == AF_INET)
    return { -1, SocketError::Unsupported };

  if (toAddr.isIPv6 && !config.enableIPv6)
    return { -1, SocketError::Unsupported };

  // Lazy open if socket is not created (UDP allows send without bind)
  if (sock == INVALID_SOCKET)
  {
    family = toAddr.isIPv6 ? AF_INET6 : AF_INET;
    sock = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
      return { -1, map_last_error() };

    if (family == AF_INET6)
    {
      BOOL v6only = config.enableIPv6 ? FALSE : TRUE;
      ::setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,
                   reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }

    if (config.nonBlocking)
    {
      u_long mode = 1;
      ::ioctlsocket(sock, FIONBIO, &mode);
      blocking = false;
    }
    else
    {
      blocking = true;
    }

    // reuseAddress for sender — optional
    if (config.reuseAddress)
    {
      BOOL v = TRUE;
      ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&v), sizeof(v));
    }
  }

  sockaddr_storage addr{};
  int addrLen = 0;
  int targetFamily = AF_UNSPEC;
  if (!fill_sockaddr_storage(toAddr, toPort, family == AF_INET6, addr, targetFamily, addrLen))
    return { -1, SocketError::InvalidParam };

  int sent = ::sendto(sock,
                      reinterpret_cast<const char*>(data),
                      static_cast<int>(length),
                      0,
                      reinterpret_cast<sockaddr*>(&addr),
                      addrLen);
  if (sent == SOCKET_ERROR)
    return { -1, map_last_error() };

  return { sent, SocketError::None };
}

SocketResult WindowsUDPSocket::receive(void* buffer,
                                       std::size_t capacity,
                                       SocketAddress& fromAddr,
                                       std::uint16_t& fromPort)
{
  if (sock == INVALID_SOCKET)
    return { -1, SocketError::NotBound };
  if (buffer == nullptr || capacity == 0)
    return { -1, SocketError::InvalidParam };

  sockaddr_storage addr{};
  int len = sizeof(addr);
  int got = ::recvfrom(sock,
                       reinterpret_cast<char*>(buffer),
                       static_cast<int>(capacity),
                       0,
                       reinterpret_cast<sockaddr*>(&addr),
                       &len);
  if (got == SOCKET_ERROR)
    return { -1, map_last_error() };

  fromAddr = socketaddress_from_sockaddr(addr);
  if (addr.ss_family == AF_INET)
    fromPort = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
  else if (addr.ss_family == AF_INET6)
    fromPort = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
  else
    fromPort = 0;
  return { got, SocketError::None };
}

void WindowsUDPSocket::poll(ISocketEventHandler* handler)
{
  if (handler == nullptr || sock == INVALID_SOCKET)
    return;

  // Single read loop until WouldBlock
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

SocketError WindowsUDPSocket::setBlocking(bool enable)
{
  if (sock == INVALID_SOCKET)
    return SocketError::NotBound;

  u_long mode = enable ? 0 : 1;
  if (::ioctlsocket(sock, FIONBIO, &mode) != 0)
    return map_last_error();

  blocking = enable;
  return SocketError::None;
}

bool WindowsUDPSocket::isBlocking() const
{
  return blocking;
}

std::uint16_t WindowsUDPSocket::localPort() const
{
  return boundPort;
}

SocketType WindowsUDPSocket::type() const
{
  return SocketType::UDP;
}

int WindowsUDPSocket::nativeHandle() const
{
  return static_cast<int>(sock);
}

void WindowsUDPSocket::close()
{
  if (sock != INVALID_SOCKET)
  {
    ::closesocket(sock);
    sock = INVALID_SOCKET;
    boundPort = 0;
    family = AF_UNSPEC;
  }
}


// Windows Socket Factory
class WindowsSocketFactory : public ISocketFactory
{
public:
  std::unique_ptr<ISocket> createSocket(SocketType type,
                                        const SocketConfig& cfg) override
  {
    switch (type)
    {
      case SocketType::UDP:
        return std::make_unique<WindowsUDPSocket>(cfg);
      case SocketType::TCP:
        // TODO: add TCP socket implementation (WindowsTCPSocket)
        return nullptr;
      default:
        return nullptr;
    }
  }
};


// Public function to register the factory. Call once during network layer initialization.
void register_windows_socket_factory()
{
  static WindowsSocketFactory factory;
  SocketFactoryRegistry::setFactory(&factory);
}

} // namespace socketwire

#endif // __clangd__