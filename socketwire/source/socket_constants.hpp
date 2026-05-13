#pragma once

// #include "socket_constants.hpp"
// auto addr = SocketConstants::any();

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace socketwire {

// Forward declaration
struct SocketAddress;

class SocketConstants {
 public:
  SocketConstants() = delete;  // Static class, no instantiation

  // IPv4 address constants (in host byte order)
  static constexpr std::uint32_t kIpV4Any = 0x00000000;       // 0.0.0.0
  static constexpr std::uint32_t kIpV4Loopback = 0x7F000001;  // 127.0.0.1
  static constexpr std::uint32_t kIpV4Broadcast =
      0xFFFFFFFF;  // 255.255.255.255

  // IPv6 address constants (network byte order)
  static inline constexpr std::array<std::uint8_t, 16> kIpV6Any = {
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};  // ::
  static inline constexpr std::array<std::uint8_t, 16> kIpV6Loopback = {
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};  // ::1

  // Port constants
  static constexpr std::uint16_t kPortAny = 0;  // Let system choose a port

  // Convenience functions to create SocketAddress directly
  static SocketAddress Any();
  static SocketAddress Loopback();
  static SocketAddress Broadcast();
  static SocketAddress AnyIPv6();
  static SocketAddress LoopbackIPv6();

  // Parse IPv4 address from string (e.g., "192.168.1.1")
  // Returns true on success, false on parse error
  static bool ParseIPv4(const char* str, std::uint32_t& out_address);

  // Parse IPv6 address from string (e.g., "fe80::1")
  // Returns true on success, false on parse error
  static bool ParseIPv6(const char* str,
                        std::array<std::uint8_t, 16>& out_address,
                        std::uint32_t& scope_id);

  // Convert IPv4 address to string (e.g., 0x7F000001 -> "127.0.0.1")
  // Buffer must be at least 16 bytes (INET_ADDRSTRLEN)
  static bool FormatIPv4(std::uint32_t address, char* buffer,
                         size_t buffer_size);

  // Convert IPv6 address to string (e.g., ::1)
  // Buffer must be at least 46 bytes (INET6_ADDRSTRLEN)
  static bool FormatIPv6(const std::array<std::uint8_t, 16>& address,
                         std::uint32_t scope_id, char* buffer,
                         size_t buffer_size);

  // Helper to create SocketAddress from string (IPv4 or IPv6)
  // Returns the address, or 0.0.0.0 on failure (prefer tryFromString for error
  // handling)
  static SocketAddress FromString(const char* ip_string);

  // Returns std::nullopt if the string is not a valid IPv4 or IPv6 address
  static std::optional<SocketAddress> TryFromString(const char* ip_string);

  // Format IPv4 as std::string
  static std::string FormatIPv4String(std::uint32_t address);

  // Format IPv6 as std::string
  static std::string FormatIPv6String(
      const std::array<std::uint8_t, 16>& address, std::uint32_t scope_id = 0);

  // Helper to create SocketAddress from individual octets
  static SocketAddress FromOctets(std::uint8_t a, std::uint8_t b,
                                  std::uint8_t c, std::uint8_t d);
};

}  // namespace socketwire
