#include "socket_constants.hpp"
#include "i_socket.hpp"

// Platform-specific includes are isolated here, not exposed to users
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#endif

namespace socketwire
{

SocketAddress SocketConstants::any()
{
  return SocketAddress::fromIPv4(IPV4_ANY);
}

SocketAddress SocketConstants::anyIPv6()
{
  return SocketAddress::fromIPv6(IPV6_ANY);
}

SocketAddress SocketConstants::loopback()
{
  return SocketAddress::fromIPv4(IPV4_LOOPBACK);
}

SocketAddress SocketConstants::loopbackIPv6()
{
  return SocketAddress::fromIPv6(IPV6_LOOPBACK);
}

SocketAddress SocketConstants::broadcast()
{
  return SocketAddress::fromIPv4(IPV4_BROADCAST);
}

bool SocketConstants::parseIPv4(const char* str, std::uint32_t& outAddress)
{
  if (str == nullptr)
    return false;

#if defined(_WIN32)
  // Windows: use inet_pton
  struct in_addr addr;
  if (inet_pton(AF_INET, str, &addr) != 1)
    return false;

  // Convert from network byte order to host byte order
  outAddress = ntohl(addr.s_addr);
  return true;
#else
  // POSIX: use inet_pton
  struct in_addr addr;
  if (inet_pton(AF_INET, str, &addr) != 1)
    return false;

  // Convert from network byte order to host byte order
  outAddress = ntohl(addr.s_addr);
  return true;
#endif
}

bool SocketConstants::parseIPv6(const char* str, std::array<std::uint8_t, 16>& outAddress, std::uint32_t& scopeId)
{
  if (str == nullptr)
    return false;

#if defined(_WIN32)
  struct in6_addr addr{};
#else
  struct in6_addr addr{};
#endif

  if (inet_pton(AF_INET6, str, &addr) != 1)
    return false;

  std::memcpy(outAddress.data(), &addr, outAddress.size());
  scopeId = 0; // inet_pton does not encode scope id
  return true;
}

bool SocketConstants::formatIPv4(std::uint32_t address, char* buffer, size_t bufferSize)
{
  if (buffer == nullptr || bufferSize < 16) // INET_ADDRSTRLEN = 16
    return false;

#if defined(_WIN32)
  struct in_addr addr;
  addr.s_addr = htonl(address);

  return inet_ntop(AF_INET, &addr, buffer, static_cast<socklen_t>(bufferSize)) != nullptr;
#else
  struct in_addr addr;
  addr.s_addr = htonl(address);

  return inet_ntop(AF_INET, &addr, buffer, static_cast<socklen_t>(bufferSize)) != nullptr;
#endif
}

bool SocketConstants::formatIPv6(const std::array<std::uint8_t, 16>& address,
                                 std::uint32_t scopeId,
                                 char* buffer,
                                 size_t bufferSize)
{
  if (buffer == nullptr || bufferSize < 46) // INET6_ADDRSTRLEN = 46
    return false;

  struct in6_addr addr{};
  std::memcpy(&addr, address.data(), address.size());
  (void)scopeId; // Scope not encoded by inet_ntop
  return inet_ntop(AF_INET6, &addr, buffer, static_cast<socklen_t>(bufferSize)) != nullptr;
}

SocketAddress SocketConstants::fromString(const char* ipString)
{
  std::uint32_t addr = 0;
  if (parseIPv4(ipString, addr))
  {
    return SocketAddress::fromIPv4(addr);
  }

  std::array<std::uint8_t, 16> addr6{};
  std::uint32_t scopeId = 0;
  if (parseIPv6(ipString, addr6, scopeId))
  {
    return SocketAddress::fromIPv6(addr6, scopeId);
  }
  // Return 0.0.0.0 on parse failure
  return SocketAddress::fromIPv4(IPV4_ANY);
}

SocketAddress SocketConstants::fromOctets(std::uint8_t a, std::uint8_t b,
                                           std::uint8_t c, std::uint8_t d)
{
  std::uint32_t address = (static_cast<std::uint32_t>(a) << 24) |
                          (static_cast<std::uint32_t>(b) << 16) |
                          (static_cast<std::uint32_t>(c) << 8)  |
                          static_cast<std::uint32_t>(d);

  return SocketAddress::fromIPv4(address);
}

} // namespace socketwire