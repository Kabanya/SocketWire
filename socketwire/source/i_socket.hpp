#pragma once

/// Cross-platform socket abstraction for the network layer.
///
/// This header exposes interfaces and structures only. Platform-specific
/// implementations live in POSIX and Windows translation units.

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
#define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
#define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

namespace socketwire {

/// Error codes returned by socket operations.
enum class SocketError : std::uint8_t {
  kNone = 0,
  kWouldBlock,    ///< Operation would block in non-blocking mode.
  kClosed,        ///< Socket is closed.
  kSystem,        ///< Low-level system error.
  kInvalidParam,  ///< Invalid arguments.
  kNotBound,      ///< Operation requires a prior Bind().
  kUnsupported,   ///< Unsupported operation or option.
  kUnknown        ///< Unclassified error.
};

/// Converts SocketError to a human-readable string.
[[nodiscard]] const char* ToString(SocketError error) noexcept;

/// Result of a send or receive operation.
struct SocketResult {
  std::ptrdiff_t bytes = 0;  ///< Number of bytes, or -1 on error.
  SocketError error = SocketError::kNone;

  [[nodiscard]] constexpr bool Succeeded() const {
    return error == SocketError::kNone;
  }
  [[nodiscard]] constexpr bool Failed() const {
    return error != SocketError::kNone;
  }
};

/// IPv4 address stored in host byte order.
struct SocketAddressIPv4 {
  std::uint32_t hostOrderAddress =
    0;  // address in host-order (e.g., result of inet_addr conversions)
};

/// IPv6 address stored in network byte order.
struct SocketAddressIPv6 {
  std::array<std::uint8_t, 16> bytes{};  // Network-order bytes
  std::uint32_t scopeId = 0;             // Scope ID for link-local addresses
};

/// Socket address supporting IPv4 and IPv6.
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

/// Datagram descriptor used by optional batched socket sends.
struct OutgoingDatagram {
  const void* data = nullptr;
  std::size_t size = 0;
  SocketAddress toAddr{};
  std::uint16_t toPort = 0;
};

/// Datagram descriptor used by optional batched socket receives.
struct IncomingDatagram {
  void* data = nullptr;
  std::size_t capacity = 0;
  SocketAddress fromAddr{};
  std::uint16_t fromPort = 0;
  SocketResult result{};
};

/// Socket creation options.
struct SocketConfig {
  bool nonBlocking = true;
  bool reuseAddress = true;
  bool enableIPv6 = false;  // enable IPv6 / dual-stack sockets
  int sendBufferSize = 0;   // 0 = keep default
  int recvBufferSize = 0;
  // Later: QoS, DSCP, broadcast, multicast, etc.
};

/// Browser WebSocket client creation options.
///
/// This transport is intended for Emscripten/browser clients. It exposes
/// binary WebSocket messages through the datagram-shaped ISocket API so the
/// reliable protocol can run without a separate transport abstraction.
struct WebSocketConfig {
  std::string url;        ///< ws:// or wss:// endpoint.
  std::string protocols;  ///< Optional comma-separated subprotocol list.
  bool createOnMainThread = true;
  std::size_t maxQueuedMessages = 256;
  std::size_t maxMessageSize = static_cast<std::size_t>(64 * 1024);
};

/// Base socket interface.
class ISocket {
 public:
  virtual ~ISocket() = default;

  /// Binds an address and host-order port.
  virtual SocketError Bind(const SocketAddress& address,
                           std::uint16_t port) = 0;

  /// Sends a datagram or stream data to a specific address and port.
  virtual SocketResult SendTo(const void* data, std::size_t length,
                              const SocketAddress& to_addr,
                              std::uint16_t to_port) = 0;

  /// Sends multiple datagrams. Implementations may override this with native
  /// batch I/O; the default path preserves existing single-send behavior.
  virtual std::size_t SendMany(std::span<const OutgoingDatagram> datagrams) {
    std::size_t sent_count = 0;
    for (const auto& datagram : datagrams) {
      const SocketResult result =
        SendTo(datagram.data, datagram.size, datagram.toAddr, datagram.toPort);
      if (result.Failed()) break;
      ++sent_count;
    }
    return sent_count;
  }

  /// Sends data from a span.
  SocketResult SendTo(std::span<const std::uint8_t> data,
                      const SocketAddress& to_addr, std::uint16_t to_port) {
    return SendTo(data.data(), data.size(), to_addr, to_port);
  }

  /// Receives data and fills the source address and port.
  virtual SocketResult Receive(void* buffer, std::size_t capacity,
                               SocketAddress& from_addr,
                               std::uint16_t& from_port) = 0;

  /// Receives multiple datagrams. Implementations may override this with
  /// native batch I/O; the default path reads until WouldBlock/error or until
  /// the provided span is full.
  virtual std::size_t ReceiveMany(std::span<IncomingDatagram> datagrams) {
    std::size_t received_count = 0;
    for (auto& datagram : datagrams) {
      datagram.result = Receive(datagram.data, datagram.capacity,
                                datagram.fromAddr, datagram.fromPort);
      if (datagram.result.Failed()) break;
      if (datagram.result.bytes <= 0) break;
      ++received_count;
    }
    return received_count;
  }

  /// Receives data into a span.
  SocketResult Receive(std::span<std::uint8_t> buffer, SocketAddress& from_addr,
                       std::uint16_t& from_port) {
    return Receive(buffer.data(), buffer.size(), from_addr, from_port);
  }

  /// Updates blocking mode.
  virtual SocketError SetBlocking(bool enable) = 0;
  [[nodiscard]] virtual bool IsBlocking() const = 0;

  /// Returns the local port, or 0 if not bound.
  [[nodiscard]] virtual std::uint16_t LocalPort() const = 0;

  /// Returns the native descriptor. Use with caution.
  [[nodiscard]] virtual int NativeHandle() const = 0;

  /// Closes the socket.
  virtual void Close() = 0;
};

/// Platform-dependent socket factory.
class ISocketFactory {
 public:
  virtual ~ISocketFactory() = default;

  virtual std::unique_ptr<ISocket> CreateUdpSocket(const SocketConfig& cfg) = 0;
};

/// Global access to the registered socket factory.
///
/// Threading/lifetime contract: SetFactory is intended for process startup.
/// Registered factories must outlive all concurrent GetFactory users; built-in
/// factories satisfy this by using function-local statics.
class SocketFactoryRegistry {
 public:
  static void SetFactory(ISocketFactory* factory);
  static ISocketFactory* GetFactory();
};

/// Registers the POSIX socket factory implementation.
void RegisterPosixSocketFactory();

/// Registers the Windows socket factory implementation.
void RegisterWindowsSocketFactory();

/// Registers the Emscripten WebSocket socket factory implementation.
void RegisterEmscriptenSocketFactory();

std::unique_ptr<ISocket> CreateEmscriptenWebSocketClient(
  const WebSocketConfig& cfg);

}  // namespace socketwire

// std::hash specialization so SocketAddress can be used as unordered_map key
namespace std {
template <>
struct hash<socketwire::SocketAddress> {
  std::size_t operator()(const socketwire::SocketAddress& a) const noexcept {
    if (a.isIPv6) {
      std::size_t seed = 0x9e3779b9u;
      for (auto b : a.ipv6.bytes) {
        seed ^=
          static_cast<std::size_t>(b) + 0x9e3779b9u + (seed << 6) + (seed >> 2);
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
