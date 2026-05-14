#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "i_socket.hpp"

namespace socketwire {

/// Common socket address constants and formatting helpers.
class SocketConstants {
 public:
  SocketConstants() = delete;

  /// IPv4 address constants in host byte order.
  static constexpr std::uint32_t kIpV4Any = 0x00000000;       ///< 0.0.0.0
  static constexpr std::uint32_t kIpV4Loopback = 0x7F000001;  ///< 127.0.0.1
  static constexpr std::uint32_t kIpV4Broadcast =
      0xFFFFFFFF;  ///< 255.255.255.255
  static constexpr std::uint32_t IPV4_ANY = kIpV4Any;
  static constexpr std::uint32_t IPV4_LOOPBACK = kIpV4Loopback;
  static constexpr std::uint32_t IPV4_BROADCAST = kIpV4Broadcast;

  /// IPv6 address constants in network byte order.
  static inline constexpr std::array<std::uint8_t, 16> kIpV6Any = {
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};  ///< ::
  static inline constexpr std::array<std::uint8_t, 16> kIpV6Loopback = {
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};  ///< ::1

  /// Lets the system choose a port.
  static constexpr std::uint16_t kPortAny = 0;
  static constexpr std::uint16_t PORT_ANY = kPortAny;

  static SocketAddress Any();
  static SocketAddress any() { return Any(); }
  static SocketAddress Loopback();
  static SocketAddress loopback() { return Loopback(); }
  static SocketAddress Broadcast();
  static SocketAddress broadcast() { return Broadcast(); }
  static SocketAddress AnyIPv6();
  static SocketAddress anyIPv6() { return AnyIPv6(); }
  static SocketAddress LoopbackIPv6();
  static SocketAddress loopbackIPv6() { return LoopbackIPv6(); }

  /// Parses an IPv4 address string.
  static bool ParseIPv4(const char* str, std::uint32_t& out_address);
  static bool parseIPv4(const char* str, std::uint32_t& out_address) {
    return ParseIPv4(str, out_address);
  }

  /// Parses an IPv6 address string.
  static bool ParseIPv6(const char* str,
                        std::array<std::uint8_t, 16>& out_address,
                        std::uint32_t& scope_id);
  static bool parseIPv6(const char* str,
                        std::array<std::uint8_t, 16>& out_address,
                        std::uint32_t& scope_id) {
    return ParseIPv6(str, out_address, scope_id);
  }

  /// Formats an IPv4 address into a buffer of at least INET_ADDRSTRLEN bytes.
  static bool FormatIPv4(std::uint32_t address, char* buffer,
                         std::size_t buffer_size);
  static bool formatIPv4(std::uint32_t address, char* buffer,
                         std::size_t buffer_size) {
    return FormatIPv4(address, buffer, buffer_size);
  }

  /// Formats an IPv6 address into a buffer of at least INET6_ADDRSTRLEN bytes.
  static bool FormatIPv6(const std::array<std::uint8_t, 16>& address,
                         std::uint32_t scope_id, char* buffer,
                         std::size_t buffer_size);
  static bool formatIPv6(const std::array<std::uint8_t, 16>& address,
                         std::uint32_t scope_id, char* buffer,
                         std::size_t buffer_size) {
    return FormatIPv6(address, scope_id, buffer, buffer_size);
  }

  /// Parses an IPv4 or IPv6 address, returning 0.0.0.0 on failure.
  static SocketAddress FromString(const char* ip_string);
  static SocketAddress fromString(const char* ip_string) {
    return FromString(ip_string);
  }

  /// Parses an IPv4 or IPv6 address, or returns std::nullopt on failure.
  static std::optional<SocketAddress> TryFromString(const char* ip_string);
  static std::optional<SocketAddress> tryFromString(const char* ip_string) {
    return TryFromString(ip_string);
  }

  /// Formats an IPv4 address as a string.
  static std::string FormatIPv4String(std::uint32_t address);
  static std::string formatIPv4String(std::uint32_t address) {
    return FormatIPv4String(address);
  }

  /// Formats an IPv6 address as a string.
  static std::string FormatIPv6String(
      const std::array<std::uint8_t, 16>& address, std::uint32_t scope_id = 0);
  static std::string formatIPv6String(
      const std::array<std::uint8_t, 16>& address,
      std::uint32_t scope_id = 0) {
    return FormatIPv6String(address, scope_id);
  }

  /// Creates an IPv4 address from individual octets.
  static SocketAddress FromOctets(std::uint8_t a, std::uint8_t b,
                                  std::uint8_t c, std::uint8_t d);
  static SocketAddress fromOctets(std::uint8_t a, std::uint8_t b,
                                  std::uint8_t c, std::uint8_t d) {
    return FromOctets(a, b, c, d);
  }
};

}  // namespace socketwire
