#include "socket_constants.hpp"

#include <optional>
#include <string>

#include "i_socket.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#if !defined(__EMSCRIPTEN__)
#include <net/if.h>
#endif
#include <sys/socket.h>

#include <cstring>
#endif

namespace socketwire::socket_constants {
namespace {

bool ParseScopeId(const std::string& scope, std::uint32_t& scope_id) {
  if (scope.empty()) return false;

  std::uint64_t numeric_scope = 0;
  bool numeric = true;
  for (const char ch : scope) {
    if (ch < '0' || ch > '9') {
      numeric = false;
      break;
    }
    numeric_scope = numeric_scope * 10 + static_cast<unsigned>(ch - '0');
    if (numeric_scope > UINT32_MAX) return false;
  }

  if (numeric) {
    scope_id = static_cast<std::uint32_t>(numeric_scope);
    return true;
  }

#if defined(_WIN32)
  const unsigned long index = if_nametoindex(scope.c_str());
  if (index == 0) return false;
  scope_id = static_cast<std::uint32_t>(index);
  return true;
#elif defined(__EMSCRIPTEN__)
  return false;
#else
  const unsigned int index = if_nametoindex(scope.c_str());
  if (index == 0) return false;
  scope_id = static_cast<std::uint32_t>(index);
  return true;
#endif
}

}  // namespace

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

  const std::string input(str);
  const auto scope_separator = input.find('%');
  const std::string address =
    scope_separator == std::string::npos ? input : input.substr(0, scope_separator);
  if (address.empty()) return false;

#if defined(_WIN32)
  struct in6_addr addr{};
#else
  struct in6_addr addr{};
#endif

  if (inet_pton(AF_INET6, address.c_str(), &addr) != 1) return false;

  scope_id = 0;
  if (scope_separator != std::string::npos) {
    const std::string scope = input.substr(scope_separator + 1);
    if (!ParseScopeId(scope, scope_id)) return false;
  }

  std::memcpy(out_address.data(), &addr, out_address.size());
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
  if (buffer == nullptr) {
    return false;
  }

  struct in6_addr addr{};
  std::memcpy(&addr, address.data(), address.size());
  char address_buffer[46];
  if (inet_ntop(AF_INET6, &addr, address_buffer, sizeof(address_buffer)) ==
      nullptr) {
    return false;
  }

  std::string formatted(address_buffer);
  if (scope_id != 0) {
    formatted += "%";
    formatted += std::to_string(scope_id);
  }

  if (formatted.size() + 1 > buffer_size) return false;
  std::memcpy(buffer, formatted.c_str(), formatted.size() + 1);
  return true;
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
  char buf[64];
  if (!FormatIPv6(address, scope_id, buf, sizeof(buf))) return {};
  return {buf};
}

}  // namespace socketwire::socket_constants
