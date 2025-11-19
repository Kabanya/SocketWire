#include "i_socket.hpp"

#include <cstring>
#include <cassert>

#if !defined(_WIN32) && !defined(_WIN64)
  #error "windows_udp_socket.cpp is for Windows platforms only."
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

// Link with Winsock library (MSVC only, GCC uses CMake target_link_libraries)
#ifdef _MSC_VER
  #pragma comment(lib, "ws2_32.lib")
#endif

namespace socketwire
{

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

// Utility: filling sockaddr_in from SocketAddress + host-order port
static void fill_sockaddr_ipv4(sockaddr_in& out,
                               const SocketAddress& address,
                               std::uint16_t portHostOrder)
{
  std::memset(&out, 0, sizeof(out));
  out.sin_family = AF_INET;
  out.sin_port = htons(portHostOrder);
  out.sin_addr.s_addr = htonl(address.ipv4.hostOrderAddress);
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

  if (sock != INVALID_SOCKET)
    return SocketError::InvalidParam; // already open

  sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET)
    return map_last_error();

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

  sockaddr_in addr{};
  fill_sockaddr_ipv4(addr, address, port);
  if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
  {
    SocketError err = map_last_error();
    ::closesocket(sock);
    sock = INVALID_SOCKET;
    return err;
  }

  // Get the actual assigned port (important when port == 0)
  sockaddr_in boundAddr{};
  int addrLen = sizeof(boundAddr);
  if (::getsockname(sock, reinterpret_cast<sockaddr*>(&boundAddr), &addrLen) == 0)
  {
    boundPort = ntohs(boundAddr.sin_port);
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

  // Lazy open if socket is not created (UDP allows send without bind)
  if (sock == INVALID_SOCKET)
  {
    sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET)
      return { -1, map_last_error() };

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

  sockaddr_in addr{};
  fill_sockaddr_ipv4(addr, toAddr, toPort);

  int sent = ::sendto(sock,
                      reinterpret_cast<const char*>(data),
                      static_cast<int>(length),
                      0,
                      reinterpret_cast<sockaddr*>(&addr),
                      sizeof(addr));
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

  sockaddr_in addr{};
  int len = sizeof(addr);
  int got = ::recvfrom(sock,
                       reinterpret_cast<char*>(buffer),
                       static_cast<int>(capacity),
                       0,
                       reinterpret_cast<sockaddr*>(&addr),
                       &len);
  if (got == SOCKET_ERROR)
    return { -1, map_last_error() };

  fromAddr = SocketAddress::fromIPv4(ntohl(addr.sin_addr.s_addr));
  fromPort = ntohs(addr.sin_port);
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