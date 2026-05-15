#pragma once
/// Shared address-conversion helpers for platform socket implementations.

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <array>
#include <cstring>

#include "i_socket.hpp"

namespace socketwire::detail {

// Detect IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
inline bool IsIpv4Mapped(const in6_addr& addr) {
  static const std::uint8_t kPrefix[12] = {0, 0, 0, 0, 0,    0,
                                           0, 0, 0, 0, 0xFF, 0xFF};
  return std::memcmp(addr.s6_addr, kPrefix, 12) == 0;
}

// Converts sockaddr_storage back to SocketAddress.
inline SocketAddress SocketAddressFromSockaddr(
  const sockaddr_storage& storage) {
  if (storage.ss_family == AF_INET) {
    const auto* addr = reinterpret_cast<const sockaddr_in*>(&storage);
    return SocketAddress::FromIPv4(ntohl(addr->sin_addr.s_addr));
  }
  if (storage.ss_family == AF_INET6) {
    const auto* addr6 = reinterpret_cast<const sockaddr_in6*>(&storage);
    if (IsIpv4Mapped(addr6->sin6_addr)) {
      std::uint32_t be = 0;
      std::memcpy(&be, addr6->sin6_addr.s6_addr + 12, sizeof(be));
      return SocketAddress::FromIPv4(ntohl(be));
    }
    std::array<std::uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), &addr6->sin6_addr, bytes.size());
    return SocketAddress::FromIPv6(bytes, addr6->sin6_scope_id);
  }
  return SocketAddress::FromIPv4(0);
}

// Fills sockaddr_storage from SocketAddress and port.
// AddrLen is socklen_t on POSIX and int on Windows.
template <typename AddrLen>
bool FillSockaddrStorage(const SocketAddress& address,
                         std::uint16_t port_host_order, bool prefer_i_pv6,
                         sockaddr_storage& storage, int& family,
                         AddrLen& addr_len) {
  std::memset(&storage, 0, sizeof(storage));

  if (address.isIPv6) {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&storage);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port_host_order);
    std::memcpy(&addr6->sin6_addr, address.ipv6.bytes.data(),
                address.ipv6.bytes.size());
    addr6->sin6_scope_id = address.ipv6.scopeId;
    family = AF_INET6;
    addr_len = static_cast<AddrLen>(sizeof(sockaddr_in6));
    return true;
  }

  if (prefer_i_pv6) {
    // Build IPv4-mapped IPv6 address ::ffff:a.b.c.d
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&storage);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port_host_order);
    addr6->sin6_addr = IN6ADDR_ANY_INIT;
    addr6->sin6_addr.s6_addr[10] = 0xFF;
    addr6->sin6_addr.s6_addr[11] = 0xFF;
    const std::uint32_t be = htonl(address.ipv4.hostOrderAddress);
    std::memcpy(addr6->sin6_addr.s6_addr + 12, &be, sizeof(be));
    family = AF_INET6;
    addr_len = static_cast<AddrLen>(sizeof(sockaddr_in6));
    return true;
  }

  auto* addr4 = reinterpret_cast<sockaddr_in*>(&storage);
  addr4->sin_family = AF_INET;
  addr4->sin_port = htons(port_host_order);
  addr4->sin_addr.s_addr = htonl(address.ipv4.hostOrderAddress);
  family = AF_INET;
  addr_len = static_cast<AddrLen>(sizeof(sockaddr_in));
  return true;
}

}  // namespace socketwire::detail
