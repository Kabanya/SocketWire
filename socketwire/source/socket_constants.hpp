#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "i_socket.hpp"

/// Common socket address constants and formatting helpers.

namespace socketwire::socket_constants {

  /// IPv4 address constants in host byte order.
  constexpr std::uint32_t kIpV4Any = 0x00000000;       ///< 0.0.0.0
  constexpr std::uint32_t kIpV4Loopback = 0x7F000001;  ///< 127.0.0.1
  constexpr std::uint32_t kIpV4Broadcast = 0xFFFFFFFF; ///< 255.255.255.255

  /// IPv6 address constants in network byte order.
  inline constexpr std::array<std::uint8_t, 16> kIpV6Any = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};  ///< ::
  inline constexpr std::array<std::uint8_t, 16> kIpV6Loopback = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};  ///< ::1

  /// Lets the system choose a port.
  constexpr std::uint16_t kPortAny = 0;

  SocketAddress Any();
  SocketAddress Loopback();
  SocketAddress Broadcast();
  SocketAddress AnyIPv6();
  SocketAddress LoopbackIPv6();

  /// Parses an IPv4 address string.
  bool ParseIPv4(const char* str, std::uint32_t& out_address);

  /// Parses an IPv6 address string.
  bool ParseIPv6(const char* str, std::array<std::uint8_t, 16>& out_address,
                 std::uint32_t& scope_id);

  /// Formats an IPv4 address into a buffer of at least INET_ADDRSTRLEN bytes.
  bool FormatIPv4(std::uint32_t address, char* buffer,
                  std::size_t buffer_size);

  /// Formats an IPv6 address into a buffer of at least INET6_ADDRSTRLEN bytes.
  bool FormatIPv6(const std::array<std::uint8_t, 16>& address,
                  std::uint32_t scope_id, char* buffer,
                  std::size_t buffer_size);

  /// Parses an IPv4 or IPv6 address, returning 0.0.0.0 on failure.
  SocketAddress FromString(const char* ip_string);

  /// Parses an IPv4 or IPv6 address, or returns std::nullopt on failure.
  std::optional<SocketAddress> TryFromString(const char* ip_string);

  /// Formats an IPv4 address as a string.
  std::string FormatIPv4String(std::uint32_t address);

  /// Formats an IPv6 address as a string.
  std::string FormatIPv6String(const std::array<std::uint8_t, 16>& address,
                               std::uint32_t scope_id = 0);

  /// Creates an IPv4 address from individual octets.
  SocketAddress FromOctets(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                           std::uint8_t d);

}  // namespace socketwire::socket_constants
