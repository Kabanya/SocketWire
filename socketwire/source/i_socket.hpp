#pragma once

/*
  Socket abstraction for cross-platform network layer.
  Goal: hide differences between platforms (POSIX / Windows), provide a unified
  interface for creating UDP/TCP sockets, event handling, and further extension
  (reliable delivery, channels, etc.).

  This file contains no implementations — only interfaces and structures.
  Implementations are created in platform-specific modules (e.g.,
  i_socket_posix.cpp / i_socket_win.cpp).
*/

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>

#if defined(_WIN32) || defined(_WIN64)
#define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
#define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

namespace socketwire {

class BitStream;  // forward declaration (for convenience: can send BitStream
                  // directly)

/* Enumeration of socket types (family/high-level protocol) */
enum class SocketType : std::uint8_t { kUdp, kTcp };

/* Possible error codes for operations */
enum class SocketError : std::uint8_t {
  kNone = 0,
  kWouldBlock,    // Operation not completed (for non-blocking mode)
  kClosed,        // Socket is closed
  kSystem,        // Low-level system error (errno / WSAGetLastError)
  kInvalidParam,  // Invalid arguments
  kNotBound,      // Operation requires prior bind()
  kUnsupported,   // Unsupported operation / option
  kUnknown        // Unclassified error
};

// Convert SocketError to human-readable string
[[nodiscard]] const char* ToString(SocketError error) noexcept;

/* Result of send/receive operation */
struct SocketResult {
  std::ptrdiff_t bytes = 0;  // Number of bytes (-1 on error)
  SocketError error = SocketError::kNone;

  [[nodiscard]] constexpr bool Succeeded() const {
    return error == SocketError::kNone;
  }
  [[nodiscard]] constexpr bool Failed() const {
    return error != SocketError::kNone;
  }
};

/*
  Address abstraction. For now — focus on IPv4.
  Can be extended to IPv6, Unix domain, etc. later.
*/
struct SocketAddressIPv4 {
  std::uint32_t hostOrderAddress =
      0;  // address in host-order (e.g., result of inet_addr conversions)
  // Utility functions for setting/getting can be implemented separately.
};

struct SocketAddressIPv6 {
  std::array<std::uint8_t, 16> bytes{};  // Network-order bytes
  std::uint32_t scopeId = 0;             // Scope ID for link-local addresses
};

// Extensible structure to support IPv6 (in the future).
struct SocketAddress {
  bool isIPv6 = false;
  SocketAddressIPv4 ipv4{};
  SocketAddressIPv6 ipv6{};

  static SocketAddress FromIPv4(std::uint32_t host_order_addr) {
    SocketAddress a;
    a.isIPv6 = false;
    a.ipv4.hostOrderAddress = host_order_addr;
    return a;
  }

  static SocketAddress FromIPv6(const std::array<std::uint8_t, 16>& bytes,
                                std::uint32_t scope_id = 0) {
    SocketAddress a;
    a.isIPv6 = true;
    a.ipv6.bytes = bytes;
    a.ipv6.scopeId = scope_id;
    return a;
  }

  bool operator==(const SocketAddress& other) const noexcept {
    if (isIPv6 != other.isIPv6) return false;
    if (isIPv6) {
      return ipv6.bytes == other.ipv6.bytes &&
             ipv6.scopeId == other.ipv6.scopeId;
    }
    return ipv4.hostOrderAddress == other.ipv4.hostOrderAddress;
  }

  bool operator!=(const SocketAddress& other) const noexcept {
    return !(*this == other);
  }
};

/* Socket configuration on creation */
struct SocketConfig {
  bool nonBlocking = true;
  bool reuseAddress = true;
  bool enableIPv6 = false;  // enable IPv6 / dual-stack sockets
  int sendBufferSize = 0;   // 0 = keep default
  int recvBufferSize = 0;
  // Later: QoS, DSCP, broadcast, multicast, etc.
};

/*
  Socket event handler interface.
  Can be registered at the level of a specific socket (for high-frequency
  events).
*/
class ISocketEventHandler {
 public:
  virtual ~ISocketEventHandler() = default;

  // Called when data is successfully read (bytesRead > 0)
  virtual void OnDataReceived(const SocketAddress& from,
                              std::uint16_t from_port, const void* data,
                              std::size_t bytes_read) = 0;

  // For sending BitStream directly (optional, if implemented)
  virtual void OnBitStreamReceived([[maybe_unused]] const SocketAddress& from,
                                   [[maybe_unused]] std::uint16_t from_port,
                                   [[maybe_unused]] BitStream& stream) {}

  // Socket error (e.g., on system failure)
  virtual void OnSocketError(SocketError error_code) = 0;

  // Event on close / connection break
  virtual void OnSocketClosed() {}
};

/*
  Base socket interface.
  Implementations: PosixSocket, WinSocket, MockSocket (for tests).
*/
class ISocket {
 public:
  virtual ~ISocket() = default;

  // Bind address (0.0.0.0 for wildcard). Port in host-order.
  virtual SocketError Bind(const SocketAddress& address,
                           std::uint16_t port) = 0;

  // For TCP: switch to listening mode. backlog — pending connections.
  virtual SocketError Listen(int backlog) {
    (void)backlog;
    return SocketError::kUnsupported;
  }

  // For TCP: accept incoming connection. Returns new socket or nullptr.
  virtual std::unique_ptr<ISocket> Accept(SocketAddress& remote_addr,
                                          std::uint16_t& remote_port) {
    (void)remote_addr;
    (void)remote_port;
    return nullptr;
  }

  // Send datagram (UDP) or data (TCP) to a specific address/port.
  virtual SocketResult SendTo(const void* data, std::size_t length,
                              const SocketAddress& to_addr,
                              std::uint16_t to_port) = 0;

  // Span overload — preferred in C++23 code.
  SocketResult SendTo(std::span<const std::uint8_t> data,
                      const SocketAddress& to_addr, std::uint16_t to_port) {
    return SendTo(data.data(), data.size(), to_addr, to_port);
  }

  // Simplified BitStream send (can be overridden for zero-copy)
  virtual SocketResult SendBitStream(BitStream& stream,
                                     const SocketAddress& to_addr,
                                     std::uint16_t to_port);

  // Receive data. Fills fromAddr/fromPort.
  virtual SocketResult Receive(void* buffer, std::size_t capacity,
                               SocketAddress& from_addr,
                               std::uint16_t& from_port) = 0;

  // Span overload — preferred in C++23 code.
  SocketResult Receive(std::span<std::uint8_t> buffer, SocketAddress& from_addr,
                       std::uint16_t& from_port) {
    return Receive(buffer.data(), buffer.size(), from_addr, from_port);
  }

  // Poll: non-blocking socket poll + generate events for handler (if
  // registered).
  virtual void Poll(ISocketEventHandler* handler) = 0;

  // Manage blocking mode
  virtual SocketError SetBlocking(bool enable) = 0;
  [[nodiscard]] virtual bool IsBlocking() const = 0;

  // Returns local port (0 if not bound)
  [[nodiscard]] virtual std::uint16_t LocalPort() const = 0;

  // Get type (TCP/UDP)
  [[nodiscard]] virtual SocketType Type() const = 0;

  // Native descriptor (fd / SOCKET). Use with caution.
  [[nodiscard]] virtual int NativeHandle() const = 0;

  // Close socket manually
  virtual void Close() = 0;
};

/*
  Default implementation of BitStream send method through the base interface:
  iterate over buffer and call SendTo.
*/
inline SocketResult ISocket::SendBitStream(BitStream& stream,
                                           const SocketAddress& to_addr,
                                           std::uint16_t to_port) {
  // Assumes GetData()/GetSizeBytes() methods in BitStream.
  extern const std::uint8_t* BitstreamAccessData(
      const BitStream&);  // can be implemented via friend
  extern std::size_t BitstreamAccessSize(const BitStream&);

  const std::uint8_t* data_ptr = BitstreamAccessData(stream);
  const std::size_t len = BitstreamAccessSize(stream);

  if ((data_ptr == nullptr) || len == 0) {
    return SocketResult{.bytes = 0, .error = SocketError::kInvalidParam};
  }

  return SendTo(data_ptr, len, to_addr, to_port);
}

/*
  Socket factory (platform-dependent).
  Can be extended for socket pools, DI, mock for tests.
*/
class ISocketFactory {
 public:
  virtual ~ISocketFactory() = default;

  virtual std::unique_ptr<ISocket> CreateSocket(SocketType type,
                                                const SocketConfig& cfg) = 0;

  // Convenient shortcuts
  std::unique_ptr<ISocket> CreateUdpSocket(const SocketConfig& cfg) {
    return CreateSocket(SocketType::kUdp, cfg);
  }

  std::unique_ptr<ISocket> CreateTcpSocket(const SocketConfig& cfg) {
    return CreateSocket(SocketType::kTcp, cfg);
  }
};

/*
  Global access to the factory (optional, if using singleton approach).
  Implementation may store a static pointer set by platform code.
 */
class SocketFactoryRegistry {
 public:
  static void SetFactory(ISocketFactory* factory);
  static ISocketFactory* GetFactory();
};

/*
  Platform-specific socket factory registration.
  Call this function to register the POSIX socket factory implementation.
 */
void RegisterPosixSocketFactory();

/*
  Platform-specific socket factory registration for Windows.
  Call this function to register the Windows socket factory implementation.
 */
void RegisterWindowsSocketFactory();

}  // namespace socketwire

// std::hash specialization so SocketAddress can be used as unordered_map key
namespace std {
template <>
struct hash<socketwire::SocketAddress> {
  std::size_t operator()(const socketwire::SocketAddress& a) const noexcept {
    if (a.isIPv6) {
      std::size_t seed = 0x9e3779b9u;
      for (auto b : a.ipv6.bytes) {
        seed ^= static_cast<std::size_t>(b) + 0x9e3779b9u + (seed << 6) +
                (seed >> 2);
      }
      seed ^= static_cast<std::size_t>(a.ipv6.scopeId) + 0x9e3779b9u +
              (seed << 6) + (seed >> 2);
      return seed;
    }
    // IPv4: mix address bits
    auto v = static_cast<std::size_t>(a.ipv4.hostOrderAddress);
    v ^= v >> 16;
    v *= 0x45d9f3bu;
    v ^= v >> 16;
    return v;
  }
};
}  // namespace std
