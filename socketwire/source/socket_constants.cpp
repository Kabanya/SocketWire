#include "socket_constants.hpp"

#include <optional>

#include "i_socket.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>
#endif

namespace socketwire::SocketConstants {

SocketAddress Any() {
  return SocketAddress::FromIPv4(kIpV4Any);
}

SocketAddress AnyIPv6() {
  return SocketAddress::FromIPv6(kIpV6Any);
}

SocketAddress Loopback() {
  return SocketAddress::FromIPv4(kIpV4Loopback);
}

SocketAddress LoopbackIPv6() {
  return SocketAddress::FromIPv6(kIpV6Loopback);
}

SocketAddress Broadcast() {
  return SocketAddress::FromIPv4(kIpV4Broadcast);
}

bool ParseIPv4(const char* str, std::uint32_t& out_address) {
  if (str == nullptr) return false;

#if defined(_WIN32)
  struct in_addr addr{};
  if (inet_pton(AF_INET, str, &addr) != 1) return false;

  out_address = ntohl(addr.s_addr);
  return true;
#else
  struct in_addr addr{};
  if (inet_pton(AF_INET, str, &addr) != 1) return false;

  out_address = ntohl(addr.s_addr);
  return true;
#endif
}

bool ParseIPv6(const char* str, std::array<std::uint8_t, 16>& out_address,
               std::uint32_t& scope_id) {
  if (str == nullptr) return false;

#if defined(_WIN32)
  struct in6_addr addr{};
#else
  struct in6_addr addr{};
#endif

  if (inet_pton(AF_INET6, str, &addr) != 1) return false;

  std::memcpy(out_address.data(), &addr, out_address.size());
  scope_id = 0;
  return true;
}

bool FormatIPv4(std::uint32_t address, char* buffer,
                std::size_t buffer_size) {
  if (buffer == nullptr || buffer_size < 16) {
    return false;
  }

#if defined(_WIN32)
  struct in_addr addr{};
  addr.s_addr = htonl(address);

  return inet_ntop(AF_INET, &addr, buffer,
                   static_cast<socklen_t>(buffer_size)) != nullptr;
#else
  struct in_addr addr{};
  addr.s_addr = htonl(address);

  return inet_ntop(AF_INET, &addr, buffer,
                   static_cast<socklen_t>(buffer_size)) != nullptr;
#endif
}

bool FormatIPv6(const std::array<std::uint8_t, 16>& address,
                std::uint32_t scope_id, char* buffer,
                std::size_t buffer_size) {
  if (buffer == nullptr || buffer_size < 46) {
    return false;
  }

  struct in6_addr addr{};
  std::memcpy(&addr, address.data(), address.size());
  (void)scope_id;
  return inet_ntop(AF_INET6, &addr, buffer,
                   static_cast<socklen_t>(buffer_size)) != nullptr;
}

SocketAddress FromString(const char* ip_string) {
  std::uint32_t addr = 0;
  if (ParseIPv4(ip_string, addr)) {
    return SocketAddress::FromIPv4(addr);
  }

  std::array<std::uint8_t, 16> addr6{};
  std::uint32_t scope_id = 0;
  if (ParseIPv6(ip_string, addr6, scope_id)) {
    return SocketAddress::FromIPv6(addr6, scope_id);
  }

  return SocketAddress::FromIPv4(kIpV4Any);
}

SocketAddress FromOctets(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                          std::uint8_t d) {
  std::uint32_t address = (static_cast<std::uint32_t>(a) << 24) |
                          (static_cast<std::uint32_t>(b) << 16) |
                          (static_cast<std::uint32_t>(c) << 8) |
                          static_cast<std::uint32_t>(d);

  return SocketAddress::FromIPv4(address);
}

std::optional<SocketAddress> TryFromString(const char* ip_string) {
  if (ip_string == nullptr) return std::nullopt;

  std::uint32_t addr = 0;
  if (ParseIPv4(ip_string, addr)) return SocketAddress::FromIPv4(addr);

  std::array<std::uint8_t, 16> addr6{};
  std::uint32_t scope_id = 0;
  if (ParseIPv6(ip_string, addr6, scope_id)) {
    return SocketAddress::FromIPv6(addr6, scope_id);
  }

  return std::nullopt;
}

std::string FormatIPv4String(std::uint32_t address) {
  char buf[16];
  if (!FormatIPv4(address, buf, sizeof(buf))) return {};
  return {buf};
}

std::string FormatIPv6String(const std::array<std::uint8_t, 16>& address,
                             std::uint32_t scope_id) {
  char buf[46];
  if (!FormatIPv6(address, scope_id, buf, sizeof(buf))) return {};
  return {buf};
}

}  // namespace socketwire::SocketConstants
