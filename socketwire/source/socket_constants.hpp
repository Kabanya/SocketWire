#pragma once

//#include "socket_constants.hpp"
//auto addr = SocketConstants::any();

#include <cstdint>
#include <cstddef>
#include <array>

namespace socketwire
{

// Forward declaration
struct SocketAddress;

class SocketConstants
{
public:
  // IPv4 address constants (in host byte order)
  static constexpr std::uint32_t IPV4_ANY = 0x00000000;        // 0.0.0.0
  static constexpr std::uint32_t IPV4_LOOPBACK = 0x7F000001;   // 127.0.0.1
  static constexpr std::uint32_t IPV4_BROADCAST = 0xFFFFFFFF;  // 255.255.255.255

  // IPv6 address constants (network byte order)
  static inline constexpr std::array<std::uint8_t, 16> IPV6_ANY = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } };        // ::
  static inline constexpr std::array<std::uint8_t, 16> IPV6_LOOPBACK = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };   // ::1

  // Port constants
  static constexpr std::uint16_t PORT_ANY = 0;  // Let system choose a port

  // Convenience functions to create SocketAddress directly
  static SocketAddress any();
  static SocketAddress loopback();
  static SocketAddress broadcast();
  static SocketAddress anyIPv6();
  static SocketAddress loopbackIPv6();

  // Parse IPv4 address from string (e.g., "192.168.1.1")
  // Returns true on success, false on parse error
  static bool parseIPv4(const char* str, std::uint32_t& outAddress);

  // Parse IPv6 address from string (e.g., "fe80::1")
  // Returns true on success, false on parse error
  static bool parseIPv6(const char* str, std::array<std::uint8_t, 16>& outAddress, std::uint32_t& scopeId);

  // Convert IPv4 address to string (e.g., 0x7F000001 -> "127.0.0.1")
  // Buffer must be at least 16 bytes (INET_ADDRSTRLEN)
  static bool formatIPv4(std::uint32_t address, char* buffer, size_t bufferSize);

  // Convert IPv6 address to string (e.g., ::1)
  // Buffer must be at least 46 bytes (INET6_ADDRSTRLEN)
  static bool formatIPv6(const std::array<std::uint8_t, 16>& address, std::uint32_t scopeId,
                         char* buffer, size_t bufferSize);

  // Helper to create SocketAddress from string (IPv4 or IPv6)
  static SocketAddress fromString(const char* ipString);

  // Helper to create SocketAddress from individual octets
  static SocketAddress fromOctets(std::uint8_t a, std::uint8_t b,
                                   std::uint8_t c, std::uint8_t d);

private:
  SocketConstants() = delete;  // Static class, no instantiation
};

} // namespace socketwire