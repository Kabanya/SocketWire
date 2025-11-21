#include "socket_constants.hpp"
#include "i_socket.hpp"

// Platform-specific includes are isolated here, not exposed to users
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
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

SocketAddress SocketConstants::loopback()
{
  return SocketAddress::fromIPv4(IPV4_LOOPBACK);
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

SocketAddress SocketConstants::fromString(const char* ipv4String)
{
  std::uint32_t addr = 0;
  if (parseIPv4(ipv4String, addr))
  {
    return SocketAddress::fromIPv4(addr);
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