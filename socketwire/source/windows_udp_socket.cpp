#include "i_socket.hpp"

#ifdef __clangd__
namespace socketwire {
void RegisterWindowsSocketFactory() {}
}  // namespace socketwire
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

namespace socketwire {

// Global WSA initialization helper
class WSAInitializer {
public:
  WSAInitializer() {
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    initialized = (result == 0);
  }

  ~WSAInitializer() {
    if (initialized) {
      WSACleanup();
    }
  }

  bool IsInitialized() const { return initialized; }

private:
  bool initialized = false;
};

static WSAInitializer& GetWsaInitializer() {
  static WSAInitializer instance;
  return instance;
}

// Error mapping WSAGetLastError -> SocketError
static SocketError MapWsaError(int wsa_error) {
  switch (wsa_error) {
    case WSAEWOULDBLOCK:
      return SocketError::kWouldBlock;
    case WSAEBADF:
    case WSAENOTSOCK:
    case WSAEINVAL:
      return SocketError::kInvalidParam;
    case WSAECONNRESET:
    case WSAENOTCONN:
    case WSAENETRESET:
    case WSAECONNABORTED:
      return SocketError::kClosed;
    case WSAENETDOWN:
    case WSAENETUNREACH:
    case WSAEHOSTDOWN:
    case WSAEHOSTUNREACH:
      return SocketError::kSystem;
    default:
      return SocketError::kSystem;
  }
}

static SocketError MapLastError() { return MapWsaError(WSAGetLastError()); }

// Windows UDP implementation based on ISocket
class WindowsUDPSocket final : public ISocket {
public:
  explicit WindowsUDPSocket(const SocketConfig& cfg);
  ~WindowsUDPSocket() override;

  SocketError Bind(const SocketAddress& address, std::uint16_t port) override;
  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override;
  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override;
  SocketError SetBlocking(bool enable) override;
  bool IsBlocking() const override;
  std::uint16_t LocalPort() const override;
  int NativeHandle() const override;
  void Close() override;

private:
  SOCKET sock_ = INVALID_SOCKET;
  bool blocking_ = false;
  std::uint16_t bound_port_ = 0;
  SocketConfig config_;
  int family_ = AF_UNSPEC;
};

WindowsUDPSocket::WindowsUDPSocket(const SocketConfig& cfg) : config_(cfg) {
  // Ensure WSA is initialized
  GetWsaInitializer();
}

WindowsUDPSocket::~WindowsUDPSocket() { Close(); }

SocketError WindowsUDPSocket::Bind(const SocketAddress& address,
                                   std::uint16_t port) {
  if (!GetWsaInitializer().IsInitialized()) return SocketError::kSystem;

  if (address.isIPv6 && !config_.enableIPv6) return SocketError::kUnsupported;
  if (config_.reusePort) return SocketError::kUnsupported;

  if (sock_ != INVALID_SOCKET)
    return SocketError::kInvalidParam;  // already open

  family_ = address.isIPv6 ? AF_INET6 : AF_INET;
  sock_ = ::socket(family_, SOCK_DGRAM, IPPROTO_UDP);
  if (sock_ == INVALID_SOCKET) return MapLastError();

  if (family_ == AF_INET6) {
    // Enable dual-stack if requested so IPv4-mapped addresses are accepted
    BOOL v6only = config_.enableIPv6 ? FALSE : TRUE;
    ::setsockopt(sock_, IPPROTO_IPV6, IPV6_V6ONLY,
                 reinterpret_cast<const char*>(&v6only), sizeof(v6only));
  }

  if (config_.reuseAddress) {
    BOOL v = TRUE;
    ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&v), sizeof(v));
  }
  if (config_.sendBufferSize > 0) {
    int size = config_.sendBufferSize;
    ::setsockopt(sock_, SOL_SOCKET, SO_SNDBUF,
                 reinterpret_cast<const char*>(&size), sizeof(size));
  }
  if (config_.recvBufferSize > 0) {
    int size = config_.recvBufferSize;
    ::setsockopt(sock_, SOL_SOCKET, SO_RCVBUF,
                 reinterpret_cast<const char*>(&size), sizeof(size));
  }

  if (config_.nonBlocking) {
    u_long mode = 1;
    ::ioctlsocket(sock_, FIONBIO, &mode);
    blocking_ = false;
  } else {
    blocking_ = true;
  }

  sockaddr_storage addr{};
  int addr_len = 0;
  int target_family = AF_UNSPEC;
  if (!detail::FillSockaddrStorage(address, port, family_ == AF_INET6, addr,
                                   target_family, addr_len)) {
    ::closesocket(sock_);
    sock_ = INVALID_SOCKET;
    family_ = AF_UNSPEC;
    return SocketError::kInvalidParam;
  }

  if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
    SocketError err = MapLastError();
    ::closesocket(sock_);
    sock_ = INVALID_SOCKET;
    family_ = AF_UNSPEC;
    return err;
  }

  // Get the actual assigned port (important when port == 0)
  sockaddr_storage bound_addr{};
  int bound_len = sizeof(bound_addr);
  if (::getsockname(sock_, reinterpret_cast<sockaddr*>(&bound_addr),
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

SocketResult WindowsUDPSocket::SendTo(const void* data, std::size_t length,
                                      const SocketAddress& to_addr,
                                      std::uint16_t to_port) {
  if (!GetWsaInitializer().IsInitialized()) return {-1, SocketError::kSystem};

  if (data == nullptr || length == 0) return {-1, SocketError::kInvalidParam};

  if (sock_ != INVALID_SOCKET && to_addr.isIPv6 && family_ == AF_INET)
    return {-1, SocketError::kUnsupported};

  if (to_addr.isIPv6 && !config_.enableIPv6)
    return {-1, SocketError::kUnsupported};

  // Lazy open if socket is not created (UDP allows send without bind)
  if (sock_ == INVALID_SOCKET) {
    family_ = to_addr.isIPv6 ? AF_INET6 : AF_INET;
    sock_ = ::socket(family_, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_ == INVALID_SOCKET) return {-1, MapLastError()};

    if (family_ == AF_INET6) {
      BOOL v6only = config_.enableIPv6 ? FALSE : TRUE;
      ::setsockopt(sock_, IPPROTO_IPV6, IPV6_V6ONLY,
                   reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }

    if (config_.nonBlocking) {
      u_long mode = 1;
      ::ioctlsocket(sock_, FIONBIO, &mode);
      blocking_ = false;
    } else {
      blocking_ = true;
    }

    if (config_.reuseAddress) {
      BOOL v = TRUE;
      ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&v), sizeof(v));
    }
  }

  sockaddr_storage addr{};
  int addr_len = 0;
  int target_family = AF_UNSPEC;
  if (!detail::FillSockaddrStorage(to_addr, to_port, family_ == AF_INET6, addr,
                                   target_family, addr_len))
    return {-1, SocketError::kInvalidParam};

  int sent = ::sendto(sock_, reinterpret_cast<const char*>(data),
                      static_cast<int>(length), 0,
                      reinterpret_cast<sockaddr*>(&addr), addr_len);
  if (sent == SOCKET_ERROR) return {-1, MapLastError()};

  return {sent, SocketError::kNone};
}

SocketResult WindowsUDPSocket::Receive(void* buffer, std::size_t capacity,
                                       SocketAddress& from_addr,
                                       std::uint16_t& from_port) {
  if (sock_ == INVALID_SOCKET) return {-1, SocketError::kNotBound};
  if (buffer == nullptr || capacity == 0)
    return {-1, SocketError::kInvalidParam};

  sockaddr_storage addr{};
  int len = sizeof(addr);
  int got = ::recvfrom(sock_, reinterpret_cast<char*>(buffer),
                       static_cast<int>(capacity), 0,
                       reinterpret_cast<sockaddr*>(&addr), &len);
  if (got == SOCKET_ERROR) return {-1, MapLastError()};

  from_addr = detail::SocketAddressFromSockaddr(addr);
  if (addr.ss_family == AF_INET)
    from_port = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
  else if (addr.ss_family == AF_INET6)
    from_port = ntohs(reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port);
  else
    from_port = 0;
  return {got, SocketError::kNone};
}

SocketError WindowsUDPSocket::SetBlocking(bool enable) {
  if (sock_ == INVALID_SOCKET) return SocketError::kNotBound;

  u_long mode = enable ? 0 : 1;
  if (::ioctlsocket(sock_, FIONBIO, &mode) != 0) return MapLastError();

  blocking_ = enable;
  return SocketError::kNone;
}

bool WindowsUDPSocket::IsBlocking() const { return blocking_; }

std::uint16_t WindowsUDPSocket::LocalPort() const { return bound_port_; }

int WindowsUDPSocket::NativeHandle() const { return static_cast<int>(sock_); }

void WindowsUDPSocket::Close() {
  if (sock_ != INVALID_SOCKET) {
    ::closesocket(sock_);
    sock_ = INVALID_SOCKET;
    bound_port_ = 0;
    family_ = AF_UNSPEC;
  }
}

class WindowsSocketFactory : public ISocketFactory {
public:
  std::unique_ptr<ISocket> CreateUdpSocket(const SocketConfig& cfg) override {
    return std::make_unique<WindowsUDPSocket>(cfg);
  }
};

// Public function to register the factory. Call once during network layer
// initialization.
void RegisterWindowsSocketFactory() {
  static WindowsSocketFactory factory;
  SocketFactoryRegistry::SetFactory(&factory);
}

}  // namespace socketwire

#endif  // __clangd__
