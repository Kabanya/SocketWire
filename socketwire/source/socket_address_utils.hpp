#pragma once
/*
  socket_address_utils.hpp — shared address-conversion helpers for platform socket implementations.
  All functions are marked `inline` to allow inclusion from multiple TUs.
*/

#if defined(_WIN32) || defined(_WIN64)
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
#endif

#include "i_socket.hpp"
#include <cstring>
#include <array>

namespace socketwire::detail
{

// Detect IPv4-mapped IPv6 address (::ffff:x.x.x.x)
inline bool is_ipv4_mapped(const in6_addr& addr)
{
  static const std::uint8_t prefix[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
  return std::memcmp(addr.s6_addr, prefix, 12) == 0;
}

// Convert sockaddr_storage back to SocketAddress
inline SocketAddress socketaddress_from_sockaddr(const sockaddr_storage& storage)
{
  if (storage.ss_family == AF_INET)
  {
    const auto* addr = reinterpret_cast<const sockaddr_in*>(&storage);
    return SocketAddress::fromIPv4(ntohl(addr->sin_addr.s_addr));
  }
  if (storage.ss_family == AF_INET6)
  {
    const auto* addr6 = reinterpret_cast<const sockaddr_in6*>(&storage);
    if (is_ipv4_mapped(addr6->sin6_addr))
    {
      std::uint32_t be = 0;
      std::memcpy(&be, addr6->sin6_addr.s6_addr + 12, sizeof(be));
      return SocketAddress::fromIPv4(ntohl(be));
    }
    std::array<std::uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), &addr6->sin6_addr, bytes.size());
    return SocketAddress::fromIPv6(bytes, addr6->sin6_scope_id);
  }
  return SocketAddress::fromIPv4(0);
}

/*
  Fill sockaddr_storage from SocketAddress + port.
  Template parameter AddrLen is socklen_t on POSIX and int on Windows.
*/
template<typename AddrLen>
bool fill_sockaddr_storage(const SocketAddress& address,
                           std::uint16_t portHostOrder,
                           bool preferIPv6,
                           sockaddr_storage& storage,
                           int& family,
                           AddrLen& addrLen)
{
  std::memset(&storage, 0, sizeof(storage));

  if (address.isIPv6)
  {
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&storage);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(portHostOrder);
    std::memcpy(&addr6->sin6_addr, address.ipv6.bytes.data(), address.ipv6.bytes.size());
    addr6->sin6_scope_id = address.ipv6.scopeId;
    family = AF_INET6;
    addrLen = static_cast<AddrLen>(sizeof(sockaddr_in6));
    return true;
  }

  if (preferIPv6)
  {
    // Build IPv4-mapped IPv6 address ::ffff:a.b.c.d
    auto* addr6 = reinterpret_cast<sockaddr_in6*>(&storage);
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(portHostOrder);
    addr6->sin6_addr = IN6ADDR_ANY_INIT;
    addr6->sin6_addr.s6_addr[10] = 0xFF;
    addr6->sin6_addr.s6_addr[11] = 0xFF;
    const std::uint32_t be = htonl(address.ipv4.hostOrderAddress);
    std::memcpy(addr6->sin6_addr.s6_addr + 12, &be, sizeof(be));
    family = AF_INET6;
    addrLen = static_cast<AddrLen>(sizeof(sockaddr_in6));
    return true;
  }

  auto* addr4 = reinterpret_cast<sockaddr_in*>(&storage);
  addr4->sin_family = AF_INET;
  addr4->sin_port = htons(portHostOrder);
  addr4->sin_addr.s_addr = htonl(address.ipv4.hostOrderAddress);
  family = AF_INET;
  addrLen = static_cast<AddrLen>(sizeof(sockaddr_in));
  return true;
}

} // namespace socketwire::detail
