#pragma once

/*
  Socket abstraction for cross-platform network layer.
  Goal: hide differences between platforms (POSIX / Windows), provide a unified interface
  for creating UDP/TCP sockets, event handling, and further extension (reliable delivery, channels, etc.).

  This file contains no implementations — only interfaces and structures.
  Implementations are created in platform-specific modules (e.g., i_socket_posix.cpp / i_socket_win.cpp).
*/

#include <cstdint>
#include <cstddef>
#include <memory>

#if defined(_WIN32) || defined(_WIN64)
  #define SOCKETWIRE_PLATFORM_WINDOWS 1
#else
  #define SOCKETWIRE_PLATFORM_WINDOWS 0
#endif

namespace socketwire
{

class BitStream; // forward declaration (for convenience: can send BitStream directly)

/* Enumeration of socket types (family/high-level protocol) */
enum class SocketType : std::uint8_t
{
  UDP,
  TCP
};

/* Possible error codes for operations */
enum class SocketError : std::uint8_t
{
  None = 0,
  WouldBlock,      // Operation not completed (for non-blocking mode)
  Closed,          // Socket is closed
  System,          // Low-level system error (errno / WSAGetLastError)
  InvalidParam,    // Invalid arguments
  NotBound,        // Operation requires prior bind()
  Unsupported,     // Unsupported operation / option
  Unknown          // Unclassified error
};

/* Result of send/receive operation */
struct SocketResult
{
  std::ptrdiff_t bytes = 0; // Number of bytes (-1 on error)
  SocketError error = SocketError::None;

  constexpr bool succeeded() const { return error == SocketError::None; }
  constexpr bool failed() const { return error != SocketError::None; }
};

/*
  Address abstraction. For now — focus on IPv4.
  Can be extended to IPv6, Unix domain, etc. later.
*/
struct SocketAddressIPv4
{
  std::uint32_t hostOrderAddress = 0; // address in host-order (e.g., result of inet_addr conversions)
  // Utility functions for setting/getting can be implemented separately.
};


// Extensible structure to support IPv6 (in the future).
struct SocketAddress
{
  bool isIPv6 = false;
  SocketAddressIPv4 ipv4{};
  // TODO: IPv6 structure (e.g., byte array[16])

  static SocketAddress fromIPv4(std::uint32_t hostOrderAddr)
  {
    SocketAddress a;
    a.isIPv6 = false;
    a.ipv4.hostOrderAddress = hostOrderAddr;
    return a;
  }
};

/* Socket configuration on creation */
struct SocketConfig
{
  bool nonBlocking = true;
  bool reuseAddress = true;
  bool enableIPv6 = false;       // reserved for future implementation
  int  sendBufferSize = 0;       // 0 = keep default
  int  recvBufferSize = 0;
  // Later: QoS, DSCP, broadcast, multicast, etc.
};

/*
  Socket event handler interface.
  Can be registered at the level of a specific socket (for high-frequency events).
*/
class ISocketEventHandler
{
public:
  virtual ~ISocketEventHandler() = default;

  // Called when data is successfully read (bytesRead > 0)
  virtual void onDataReceived(const SocketAddress& from,
                              std::uint16_t fromPort,
                              const void* data,
                              std::size_t bytesRead) = 0;

  // For sending BitStream directly (optional, if implemented)
  virtual void onBitStreamReceived([[maybe_unused]]const SocketAddress& from,
                                   [[maybe_unused]]std::uint16_t fromPort,
                                   [[maybe_unused]]BitStream& stream) {}

  // Socket error (e.g., on system failure)
  virtual void onSocketError(SocketError errorCode) = 0;

  // Event on close / connection break
  virtual void onSocketClosed() {}
};

/*
  Base socket interface.
  Implementations: PosixSocket, WinSocket, MockSocket (for tests).
*/
class ISocket
{
public:
  virtual ~ISocket() = default;

  // Bind address (0.0.0.0 for wildcard). Port in host-order.
  virtual SocketError bind(const SocketAddress& address, std::uint16_t port) = 0;

  // For TCP: switch to listening mode. backlog — pending connections.
  virtual SocketError listen(int backlog) { (void)backlog; return SocketError::Unsupported; }

  // For TCP: accept incoming connection. Returns new socket or nullptr.
  virtual std::unique_ptr<ISocket> accept(SocketAddress& remoteAddr, std::uint16_t& remotePort)
  {
    (void)remoteAddr; (void)remotePort;
    return nullptr;
  }

  // Send datagram (UDP) or data (TCP) to a specific address/port.
  virtual SocketResult sendTo(const void* data,
                              std::size_t length,
                              const SocketAddress& toAddr,
                              std::uint16_t toPort) = 0;

  // Simplified BitStream send (can be overridden for zero-copy)
  virtual SocketResult sendBitStream(BitStream& stream,
                                     const SocketAddress& toAddr,
                                     std::uint16_t toPort);

  // Receive data. Fills fromAddr/fromPort.
  virtual SocketResult receive(void* buffer,
                               std::size_t capacity,
                               SocketAddress& fromAddr,
                               std::uint16_t& fromPort) = 0;

  // Poll: non-blocking socket poll + generate events for handler (if registered).
  virtual void poll(ISocketEventHandler* handler) = 0;

  // Manage blocking mode
  virtual SocketError setBlocking(bool enable) = 0;
  virtual bool isBlocking() const = 0;

  // Returns local port (0 if not bound)
  virtual std::uint16_t localPort() const = 0;

  // Get type (TCP/UDP)
  virtual SocketType type() const = 0;

  // Native descriptor (fd / SOCKET). Use with caution.
  virtual int nativeHandle() const = 0;

  // Close socket manually
  virtual void close() = 0;
};

/*
  Default implementation of BitStream send method through the base interface:
  iterate over buffer and call sendTo.
*/
inline SocketResult ISocket::sendBitStream(BitStream& stream,
                                           const SocketAddress& toAddr,
                                           std::uint16_t toPort)
{
  // Assumes getData()/getSizeBytes() methods in BitStream.
  extern const std::uint8_t* bitstream_access_data(const BitStream&); // can be implemented via friend
  extern std::size_t bitstream_access_size(const BitStream&);

  const std::uint8_t* dataPtr = bitstream_access_data(stream);
  std::size_t len = bitstream_access_size(stream);

  if ((dataPtr == nullptr) || len == 0)
    return SocketResult{0, SocketError::InvalidParam};

  return sendTo(dataPtr, len, toAddr, toPort);
}

/*
  Socket factory (platform-dependent).
  Can be extended for socket pools, DI, mock for tests.
*/
class ISocketFactory
{
public:
  virtual ~ISocketFactory() = default;

  virtual std::unique_ptr<ISocket> createSocket(SocketType type,
                                                const SocketConfig& cfg) = 0;

  // Convenient shortcuts
  std::unique_ptr<ISocket> createUDPSocket(const SocketConfig& cfg)
  {
    return createSocket(SocketType::UDP, cfg);
  }

  std::unique_ptr<ISocket> createTCPSocket(const SocketConfig& cfg)
  {
    return createSocket(SocketType::TCP, cfg);
  }
};

/*
  Global access to the factory (optional, if using singleton approach).
  Implementation may store a static pointer set by platform code.
 */
class SocketFactoryRegistry
{
public:
  static void setFactory(ISocketFactory* factory);
  static ISocketFactory* getFactory();
};

} // namespace socketwire